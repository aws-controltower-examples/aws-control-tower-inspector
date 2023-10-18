import logging
import boto3
import botocore
from time import sleep
from botocore.exceptions import ClientError
from typing import TYPE_CHECKING, Any, Literal
import cfnresponse
import os

logger = logging.getLogger()

role_to_assume=os.environ["EXECUTION_ROLE_NAME"]
account_id=os.environ["AUDIT_ACCOUNT_ID"]
excluded_accounts=os.environ['EXCLUDED_ACCOUNTS']
org_client=boto3.client('organizations')

ENABLE_RETRY_ATTEMPTS = 10
ENABLE_RETRY_SLEEP_INTERVAL = 10

session = boto3.Session()

def assume_role(account_id, role_to_assume):
    sts_client = boto3.client('sts')
    response = sts_client.assume_role(
        RoleArn=f'arn:aws:iam::{account_id}:role/{role_to_assume}',
        RoleSessionName='EnableSecurityHub'
    )
    sts_session = boto3.Session(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken']
    )
    print(f"Assumed session for Account ID: {account_id}.")
    return sts_session


def get_control_tower_regions():
    cloudformation_client = boto3.client('cloudformation')
    control_tower_regions = set()
    try:
        stack_instances = cloudformation_client.list_stack_instances(
            StackSetName="AWSControlTowerBP-BASELINE-CONFIG"
        )
        for stack in stack_instances['Summaries']:
            control_tower_regions.add(stack['Region'])
    except ClientError as error:
        print(error)
    print(f"Control Tower Regions: {list(control_tower_regions)}")
    return list(control_tower_regions)

def get_inspector_status(inspector_client, account_id, scan_components):
    logger.info(f"get_inspector_status: scan_components - ({scan_components})")
    logger.info(f"Checking inspector service status for {account_id} account...")
    enabled_components = 0
    inspector_status_response = inspector_client.batch_get_account_status(accountIds=[account_id])
    api_call_details = {"API_Call": "inspector:BatchGetAccountStatus", "API_Response": inspector_status_response}
    logger.info(api_call_details)
    for status in inspector_status_response["accounts"]:
        if status["state"]["status"] == "ENABLED":
            logger.info(f"Status: {status['state']['status']}")
            for scan_component in scan_components:
                logger.info(f"{scan_component} status: {status['resourceState'][scan_component.lower()]['status']}")
                if status["resourceState"][scan_component.lower()]["status"] != "ENABLED":
                    logger.info(f"{scan_component} scan component is disabled...")
                else:
                    logger.info(f"{scan_component} scan component is enabled...")
                    enabled_components = enabled_components + 1
        else:
            inspector_status = "disabled"
            return inspector_status
    if 0 < enabled_components < len(scan_components):
        inspector_status = "partial"
    elif enabled_components == len(scan_components):
        inspector_status = "enabled"
    else:
        inspector_status = "disabled"
    return inspector_status
    
def get_all_accounts():
    """
    Gets a list of Active AWS Accounts in the Organization.
    This is called if the function is not executed by an Sns trigger
    and is used for periodic scheduling to ensure all accounts are
    correctly configured, and prevent gaps in security from activities
    like new regions being added or GuardDuty being disabled.
    """
    aws_account_dict = dict()
    orgclient = session.client('organizations', region_name=session.region_name)
    accounts = orgclient.list_accounts()
    while 'NextToken' in accounts:
        moreaccounts = orgclient.list_accounts(NextToken=accounts['NextToken'])
        for acct in accounts['Accounts']:
            moreaccounts['Accounts'].append(acct)
        accounts = moreaccounts
    logger.debug(accounts)
    for account in accounts['Accounts']:
        logger.debug(account)
        # Filter out suspended accounts and save valid accounts in a dict
        if account['Status'] == 'ACTIVE':
            accountid = account['Id']
            email = account['Email']
            aws_account_dict.update({accountid: email})
    return aws_account_dict

def enable_inspector2(inspector_client, account_id, region, scan_components):
    logger.info(f"enable_inspector2: scan_components - ({scan_components})")
    for attempt_iteration in range(1, ENABLE_RETRY_ATTEMPTS):
        if get_inspector_status(inspector_client, account_id, scan_components) != "enabled":
            logger.info(f"Attempt {attempt_iteration} - enabling inspector in the ({account_id}) account in {region}...")
            try:
                enable_inspector_response: Any = inspector_client.enable(
                    accountIds=[
                        account_id,
                    ],
                    resourceTypes=scan_components,
                )
                api_call_details = {"API_Call": "inspector:Enable", "API_Response": enable_inspector_response}
                logger.info(api_call_details)
                print(f"done in {accounts}")
            except inspector_client.exceptions.ConflictException:
                logger.info(f"inspector already enabled in {account_id} {region}")
        else:
            logger.info(f"Inspector is enabled in the {account_id} account in {region}")
            break
        sleep(ENABLE_RETRY_SLEEP_INTERVAL)

def lambda_handler(event, context):
    inspector_regions = boto3.Session().get_available_regions('inspector2')
    control_tower_regions = get_control_tower_regions()
    scan_components = ["EC2"] 
    accounts=get_all_accounts()
    if 'RequestType' in event:    
        if (event['RequestType'] == 'Create' or event['RequestType'] == 'Update'):
            try:
                inspector_delegated_admin=org_client.list_delegated_administrators(
                    ServicePrincipal='inspector2.amazonaws.com'
                )
                if inspector_delegated_admin['DelegatedAdministrators']:
                            print(f"Delegated Administration has already been configured for Inspector to Account ID: {inspector_delegated_admin['DelegatedAdministrators'][0]['Id']}.")
                else:
                    try:
                        org_client.register_delegated_administrator(
                            AccountId=account_id,
                            ServicePrincipal='inspector2.amazonaws.com'
                        )
                    except ClientError as error:
                            print(f"Delegated Administration for Inspector is already configured. Error: {error}.")
                    print(f"Admin Account delegated in {inspector_delegated_admin}")
                for account in accounts:
                        session = assume_role(account, role_to_assume)    
                        for region in control_tower_regions:
                            if region in inspector_regions:
                                if account not in excluded_accounts:
                                  inspector_client = session.client('inspector2', region_name=region)
                                  get_inspector_status(inspector_client, account, scan_components)  
                                  print(f"Inspector is enabled in Account {account}")
                                  enable_inspector2(inspector_client, account, region, scan_components)
                                else:
                                    print(f'Account excluded: {account}')
                            else:
                                print(f"Unable to delegate Admin account")
            except ClientError as error:
                print(error)
                cfnresponse.send(event, context, cfnresponse.FAILED, error)
        elif (event['RequestType'] == 'Delete'):
            try:
                session = assume_role(account, role_to_assume)
                for region in control_tower_regions:
                    inspector_client = session.client('inspector2', region_name=region)
                    try:
                        inspector_client.disable_organization_admin_account(
                        adminAccountId=inspector_client
                        )
                    except ClientError as error:
                        print(f"Delegated Administration for Amazon Macie has been disabled in {region}.")
                    for account in accounts:
                        if account not in excluded_accounts:
                            member_session=assume_role(account, role_to_assume)
                            member_client=member_session.client('inspector2', region_name=region)
                            inspector_admin_client=inspector_client.client('inspector2', region_name=region)
                            try:
                                inspector_admin_client.delete_member(
                                    id=account['Id']
                                )
                            except ClientError as error:
                                print(f"Unable to delete {account} in {region} as a member from Amazon Inspector as it's not enabled.")    
                    try:
                        member_client.disable_inspector()
                        print(f"Amazon inspector has been disabled in {region}.")
                    except ClientError as error:
                        print(f"Unable to disable Amazon inspector in {account} in {region} as it's not enabled.")
                cfnresponse.send(event, context, cfnresponse.SUCCESS, {})
            except ClientError as error:
                print(error)
                cfnresponse.send(event, context, cfnresponse.FAILED, error) 
        else:
            try: 
                org_client.enable_aws_service_access(
                    ServicePrincipal='inspector2.amazonaws.com'    
                )
                for region in control_tower_regions:
                    if region in inspector_regions:
                        enable_inspector2(inspector_client, account, region, scan_components)
            except ClientError as error:
                print(f"AWS Service Access has already been configured for Amazon Inspector.")
            print("done")



