#!/usr/bin/python
# Copyright (c) 2022 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


DOCUMENTATION = r'''
---
module: aws_eks_nodegroup
version_added: 1.0.0
short_description: Manage EKS Nodegroup
description:
    - Manage EKS Nodegroup
author: Tiago Jarra (@tjarra)
options:
  name:
    description: Name of EKS Nodegroup
    required: True
    type: str
  cluster_name:
    description: Name of EKS Cluster
    required: True
    type: str
  node_role:
    description: ARN of IAM role used by the EKS cluster Nodegroup
    required: True
    type: str
  subnets:
    description: list of subnet IDs for the Kubernetes cluster
    required: True
    type: list
    elements: str
  namespace:
    description: Name of Namespace 
    required: True
    type: list
    elements: str
  state:
    description: Create or delete the Fargate Profile
    choices:
      - absent
      - present
    default: present
    type: str
  wait:
    description: >-
      Specifies whether the module waits until the profile is created or deleted before moving on.
    type: bool
    default: false
  wait_timeout:
    description: >-
      The duration in seconds to wait for the cluster to become active. Defaults
      to 1200 seconds (20 minutes).
    default: 1200
    type: int
extends_documentation_fragment:
- amazon.aws.aws
- amazon.aws.ec2

'''

EXAMPLES = r'''
# Note: These examples do not set authentication details, see the AWS Guide for details.

- name: Create an EKS Fargate Profile
  community.aws.aws_eks_fargate_profile:
    name: test_fargate
    cluster_name: test_cluster
    role_arn: my_eks_role
    subnets:
      - subnet-aaaa1111
    selectors:
      - namespace: nm-test
        labels:
          - label1: test
    state: present
    wait: yes

- name: Remove an EKS cluster
  community.aws.aws_eks_cluster:
    name: test_fargate
    clusterName: test_cluster
    wait: yes
    state: absent
'''

RETURN = r'''
fargateProfileName:
  description: Name of Fargate Profile
  returned: when state is present
  type: str
  sample: test_profile
fargateProfileArn:
  description: ARN of the Fargate Profile
  returned: when state is present
  type: str
  sample: arn:aws:eks:us-east-1:1231231123:safd
clusterName:
  description: Name of EKS Cluster 
  returned: when state is present
  type: str
  sample: test-cluster
created_at:
  description: Fargate Profule creation date and time
  returned: when state is present
  type: str
  sample: '2022-01-18T20:00:00.111000+00:00'
podExecutionRoleArn:
  description: ARN of the IAM Role used by Fargate Profile
  returned: when state is present
  type: str
  sample: arn:aws:eks:us-east-1:1231231123:role/asdf
subnets:
  description: List of subnets used in Fargate Profile
  returned: when state is present
  type: list
  sample:
  - subnet-qwerty123
  - subnet-asdfg456
selectors:
  description: Selector configuration
  returned: when state is present
  type: complex
  contains:
    namespace:
      description: Name of the kubernetes namespace used in profile
      returned: when state is present
      type: str
      sample: nm-test
    labels:
      description: List of kubernetes labels used in profile
      returned: when state is present
      type: list
      sample:
        - label1: test1
        - label2: test2
status:
  description: status of the EKS Fargate Profile
  returned: when state is present
  type: str
  sample:
  - CREATING
  - ACTIVE
'''

from ansible_collections.amazon.aws.plugins.module_utils.core import AnsibleAWSModule, is_boto3_error_code
from ansible_collections.amazon.aws.plugins.module_utils.ec2 import compare_aws_tags
from ansible_collections.amazon.aws.plugins.module_utils.ec2 import camel_dict_to_snake_dict
from ansible_collections.amazon.aws.plugins.module_utils.waiters import get_waiter

try:
    import botocore.exceptions
except ImportError:
    pass  

def validate_tags(client, module, nodegroup):
  
    changed = False
    existing_tags = client.list_tags_for_resource(resourceArn=nodegroup['nodegroupArn'])
    
    tags_to_add, tags_to_remove = compare_aws_tags(existing_tags, module.params.get('tags'), module.params.get('purge_tags'))
    
    if tags_to_remove:
        if not module.check_mode:
            changed = True
            try:
                client.untag_resource(aws_retry=True, ResourceArn=nodegroup['nodegroupArn'], tagKeys=tags_to_remove)
            except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
                module.fail_json_aws(e, msg='Unable to set tags for Fargate Profile %s' % module.params.get('name'))

    if tags_to_add:
        if not module.check_mode:
            changed = True
            try:
                client.tag_resource(aws_retry=True, ResourceArn=nodegroup['nodegroupArn'], tags=tags_to_add)
            except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
                module.fail_json_aws(e, msg='Unable to set tags for Fargate Profile %s' % module.params.get('name'))
    
    return changed

def compare_taints(nodegroup_taints, param_taints):
    taints_to_unset = []
    taints_to_add_or_update = []
    for taint in nodegroup_taints:
        if taint not in param_taints:
            taints_to_unset.append(taint)
    for taint in param_taints:
        if taint not in nodegroup_taints:
            taints_to_add_or_update.append(taint)

    return taints_to_add_or_update, taints_to_unset

def validate_taints(client, module, nodegroup, param_taints):
    changed = False    
    params = dict()
    params['clusterName'] = nodegroup['clusterName'] 
    params['nodegroupName'] = nodegroup['nodegroupName'] 
    params['taints'] = {}
    taints_to_add_or_update, taints_to_unset = compare_taints(nodegroup['taints'], param_taints)
    
    if taints_to_add_or_update: 
        params['taints']['addOrUpdateTaints'] = taints_to_add_or_update 
    if taints_to_unset:
        params['taints']['removeTaints'] = taints_to_unset
    if params['taints']:
        if not module.check_mode:
            changed = True
            try:
                client.update_nodegroup_config(**params)
            except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
                module.fail_json_aws(e, msg='Unable to set taints for Nodegroup %s' % params['nodegroupName'])
    
    return changed   

def compare_labels(nodegroup_labels, param_labels):
    labels_to_unset = []
    labels_to_add_or_update = {}
    for label in nodegroup_labels.keys():
        if label not in param_labels:
            labels_to_unset.append(label)
    for key, value in param_labels.items():
        if key not in nodegroup_labels.keys():
           labels_to_add_or_update[key] = value
    
    return labels_to_add_or_update, labels_to_unset

def validate_labels(client, module, nodegroup, param_labels):
    changed = False    
    params = dict()
    params['clusterName'] = nodegroup['clusterName'] 
    params['nodegroupName'] = nodegroup['nodegroupName'] 
    params['labels'] = {}
    labels_to_add_or_update, labels_to_unset = compare_labels(nodegroup['labels'], param_labels)
    
    if labels_to_add_or_update: 
        params['labels']['addOrUpdateLabels'] = labels_to_add_or_update 
    if labels_to_unset:
        params['labels']['removeLabels'] = labels_to_unset
    if params['labels']:
        if not module.check_mode:
            changed = True
            try:
                client.update_nodegroup_config(**params)
            except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
                module.fail_json_aws(e, msg='Unable to set labels for Nodegroup %s' % params['nodegroupName'])
    
    return changed   

def create_or_update_nodegroups(client, module):
    
    changed = False
    params = dict()
    params['nodegroupName'] = module.params.get['name']
    params['clusterName'] = module.params['cluster_name']
    params['nodeRole'] = module.params['role_arn']
    params['subnets'] = module.params['subnets']
    
    # this configurations is to use default AMI in AWS, this module not prepare to lauch templates
    params['amiType'] = module.params['ami_type']
    params['diskSize'] = module.params['disk_size']
    params['instanceTypes'] = module.params['instance_types']
    params['releaseVersion'] = module.params['release_version']    
    ##
    if module.params['remote_access'] is not None:
        params['remoteAccess'] = module.params['remote_access']    
    if module.params['tags'] is not None:    
        params['tags'] = module.params['tags']
    if module.params['capacity_type'] is not None:
        params['capacityType'] = module.params['capacity_type']
    if module.params['labels'] is not None:
        params['labels'] = module.params['labels']
    if module.params['taints'] is not None:
        params['taints'] = module.params['taints']
    if module.params['update_config'] is not None:
        params['updateConfig'] = module.params['update_config']
    if module.params['scaling_config'] is not None:
        params['scalingConfig'] = module.params['scaling_config']
        
    wait = module.params.get('wait')
    nodegroup = get_nodegroup(client, module, params['nodegroupName'], params['clusterName'])
    
    try:
        ec2 = module.client('ec2')
        vpc_id = ec2.describe_subnets(SubnetIds=[params['subnets'][0]])['Subnets'][0]['VpcId']        
    except (botocore.exceptions.BotoCoreError, botocore.exceptions.ClientError) as e:
        module.fail_json_aws(e, msg="Couldn't not find subnets")

    if nodegroup:     
                
        if compare_params(client, module, params, nodegroup):
            changed = True
            try:
                update_params = dict(
                    clusterName = params['clusterName'],
                    nodegroupName = params['nodegroupName'],
                    scalingConfig = params['scalingConfig'],
                    updateConfig = params['scalingConfig']
                )
                nodegroup = client.update_nodegroup_config(**update_params)
            except (botocore.exceptions.BotoCoreError, botocore.exceptions.ClientError) as e:
                module.fail_json_aws(e, msg="Couldn't update nodegroup")

        changed |= validate_tags(client, module, nodegroup)       
        
        changed |= validate_taints(client, module, nodegroup['taints'], params['taints'])
        
        changed |= validate_labels(client, module, nodegroup['labels'], params['labels'])        
                              
        if wait:
            wait_until(client, module, 'fargate_profile_active', params['nodegroupName'], params['clusterName'])
            nodegroup = get_nodegroup(client, module, params['nodegroupName'], params['clusterName'])

        module.exit_json(changed=changed, **camel_dict_to_snake_dict(nodegroup))

    if module.check_mode:
        module.exit_json(changed=True)
  
    try:       
        nodegroup = client.create_nodegroup(**params)
    except (botocore.exceptions.BotoCoreError, botocore.exceptions.ClientError) as e:
        module.fail_json_aws(e, msg="Couldn't create Nodegroup %s" % params['nodegroupName'])

    if wait:
        wait_until(client, module, 'nodegroup_active', params['nodegroupName'], params['clusterName'])
        nodegroup = get_nodegroup(client, module, params['nodegroupName'], params['clusterName'])

    module.exit_json(changed=True, **camel_dict_to_snake_dict(nodegroup))

def compare_params(client, module, params, nodegroup):
    # First, validating the params that cannot be modified
    if nodegroup['nodeRole'] != params['nodeRole']:
        module.fail_json(msg="Cannot modify Execution Role")
    if nodegroup['subnets'] != params['subnets']:
        module.fail_json(msg="Cannot modify Subnets")
    if nodegroup['diskSize'] != params['diskSize']:
        module.fail_json(msg="Cannot modify Disk size")    
    if nodegroup['instanceTypes'] != params['instanceTypes']:
        module.fail_json(msg="Cannot modify Instance Type")
    if nodegroup['amiType'] != params['amiType']:
        module.fail_json(msg="Cannot modify AMI Type")
    if nodegroup['remoteAccess'] != params['remoteAccess']:
        module.fail_json(msg="Cannot modify remote access configuration")
    if nodegroup['capacityType'] != params['capacityType']:
        module.fail_json(msg="Cannot modify capacity type")
    if nodegroup['releaseVersion'] != params['releaseVersion']:
        module.fail_json(msg="Cannot modify release version")
    ###
    if nodegroup['updateConfig'] != params['updateConfig']:
        return True
    if nodegroup['scalingConfig'] != params['scalingConfig']:
        return True
    
    return False    

def delete_nodegroups(client, module):
    name = module.params.get('name')
    clusterName = module.params['cluster_name']
    existing = get_nodegroup(client, module, name, clusterName)
    wait = module.params.get('wait')
    if not existing:
        module.exit_json(changed=False)
    if not module.check_mode:

        try:
            client.delete_nodegroup(clusterName=clusterName,nodegroupName=name)
        except (botocore.exceptions.BotoCoreError, botocore.exceptions.ClientError) as e:
            module.fail_json_aws(e, msg="Couldn't delete Nodegroup %s" % name)

    if wait:
        wait_until(client, module, 'nodegroup_deleted', name, clusterName)

    module.exit_json(changed=True)

def get_nodegroup(client, module, name, cluster_name):    
    try:
        return client.describe_nodegroup(clusterName=cluster_name, nodegroupName=name)['nodegrouop']
    except is_boto3_error_code('ResourceNotFoundException'):
        return None
  
def wait_until(client, module, waiter_name, name, clusterName):    
    wait_timeout = module.params.get('wait_timeout')
    
    waiter = get_waiter(client, waiter_name)
    attempts = 1 + int(wait_timeout / waiter.config.delay)
    waiter.wait(clusterName=clusterName, fargateProfileName=name, WaiterConfig={'MaxAttempts': attempts})
    
def main():
    argument_spec = dict(
        name=dict(required=True),
        cluster_name=dict(required=True),
        node_role=dict(),
        subnets=dict(type='list', elements='str'),
        scaling_config=dict(type='list', options=dict(
            min_size=dict(type='int'),
            max_size=dict(type='int'),
            desire_size=dict(type='int')
        )),   
        disk_size=dict(type='integer'),
        instance_types=dict(type='list'),
        ami_type=dict(choices=['AL2_x86_64','AL2_x86_64_GPU','AL2_ARM_64','CUSTOM','BOTTLEROCKET_ARM_64','BOTTLEROCKET_x86_64']),
        remote_access=dict(type='dict', options=dict(
            ec2_ssh_key=dict(),
            source_sg=dict(type='list')
        )),
        update_config=dict(type='dict', options=dict(
            max_unavailable=dict(type='int'),
            max_unavailable_percentage=dict(type='int'),
        )),
        labels=dict(type='dict'),
        taints=dict(type='list'),
        capacity_type=dict(choices=['on_demand', 'spot'], default='on_demand'),
        release_version=dict(),     
        tags=dict(type='dict', default={}),
        purge_tags=dict(type='bool', default=True),
        state=dict(choices=['absent', 'present'], default='present'),
        wait=dict(default=False, type='bool'),
        wait_timeout=dict(default=1200, type='int')
    )

    module = AnsibleAWSModule(
        argument_spec=argument_spec,
        required_if=[['state', 'present', ['name','cluster_name', 'node_role', 'subnets', 'selectors']]],
        supports_check_mode=True,
    )

    client = module.client('eks')

    if module.params.get('state') == 'present':
        create_or_update_nodegroups(client, module)
    else:
        delete_nodegroups(client, module)

if __name__ == '__main__':
    main()