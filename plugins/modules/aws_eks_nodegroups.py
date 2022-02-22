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
    type: str
  subnets:
    description: list of subnet IDs for the Kubernetes cluster
    type: list
    elements: str
  scaling_config:
    description: The scaling configuration details for the Auto Scaling group that is created for your node group.
    type: dict
    suboptions:
      min_size:
        description: The minimum number of nodes that the managed node group can scale in to.
        type: int
      max_size:
        description: The maximum number of nodes that the managed node group can scale out to.
        type: int
      desire_size:
        description: The current number of nodes that the managed node group should maintain.
        type: int
  disk_size:
    description: Size of disk in nodegroup nodes
    type: int
  instance_types:
    description: Specify the instance types for a node group.
    type: list
    elements: str
  ami_type:
    description: The AMI type for your node group
    type: str
    choices:
      - AL2_x86_64
      - AL2_x86_64_GPU
      - AL2_ARM_64
      - CUSTOM
      - BOTTLEROCKET_ARM_64
      - BOTTLEROCKET_x86_64
  remote_access:
    description: The remote access (SSH) configuration to use with your node group.
    type: dict
    suboptions:
      ec2_ssh_key:
        description: The Amazon EC2 SSH key that provides access for SSH communication with the nodes in the managed node group
        type: str
      source_sg:
        description: The security groups that are allowed SSH access (port 22) to the nodes
        type: list
        elements: str
  update_config:
    description: The node group update configuration.
    type: dict
    suboptions:
      max_unavailable:
        description: The maximum number of nodes unavailable at once during a version update.
        type: int
      max_unavailable_percentage:
        description: The maximum percentage of nodes unavailable during a version update.
        type: int
  labels:
    description: The Kubernetes labels to be applied to the nodes in the node group when they are created.
    type: dict
  taints:
    description: The Kubernetes taints to be applied to the nodes in the node group.
    type: list
    elements: dict
  capacity_type:
    description: The capacity type for your node group.
    default: on_demand
    type: str
    choices:
      - on_demand
      - spot
  release_version:
    description: The AMI version of the Amazon EKS optimized AMI to use with your node group.
    type: str
  tags:
    description: The metadata to apply to the node group to assist with categorization and organization.
    type: dict
  purge_tags:
    description: Purge or not tags if not describe
    type: bool
    default: True
  state:
    description: Create or delete the Fargate Profile
    choices:
      - absent
      - present
    default: present
    type: str
  wait:
    description: Specifies whether the module waits until the profile is created or deleted before moving on.
    type: bool
    default: false
  wait_timeout:
    description: The duration in seconds to wait for the cluster to become active. Defaults to 1200 seconds.
    default: 1200
    type: int
extends_documentation_fragment:
- amazon.aws.aws
- amazon.aws.ec2

'''

EXAMPLES = r'''
# Note: These examples do not set authentication details, see the AWS Guide for details.

- name: create nodegroup witn minimum parameters
  community.aws.aws_eks_nodegroup:
    name: test_nodegroup
    state: present
    cluster_name: fake_cluster
    node_role: '{{ role }}'
    subnets: >-
      {{setup_subnets.results|selectattr('subnet.tags.Name', 'contains',
      'private') | map(attribute='subnet.id') }}
    scaling_config:
      - min_size: 1
      - max_size: 2
      - desire_size: 1
    disk_size: 20
    instance_types: 't3.micro'
    ami_type: 'AL2_x86_64'
    labels:
      - 'teste': 'teste'
    taints:
      - key: 'teste'
        value: 'teste'
        effect: 'NO_SCHEDULE'
    capacity_type: 'on_demand'

- name: Remove an EKS Nodegrop
  community.aws.aws_eks_nodegroup:
    name: test_nodegroup
    clusterName: test_cluster
    wait: yes
    state: absent
'''

RETURN = r'''
nodegroupName:
  description: The name associated with an Amazon EKS managed node group.
  returned: when state is present
  type: str
  sample: test_profile
nodegroupArn:
  description: The Amazon Resource Name (ARN) associated with the managed node group.
  returned: when state is present
  type: str
  sample: arn:aws:eks:us-east-1:1231231123:safd
clusterName:
  description: Name of EKS Cluster
  returned: when state is present
  type: str
  sample: test-cluster
version:
  description: The Kubernetes version of the managed node group.
  returned: when state is present
  type: str
  sample: need_validate
releaseVersion:
  description: This is the version of the Amazon EKS optimized AMI that the node group was deployed with
  returned: when state is present
  type: str
  sample: need_validate
created_at:
  description: Nodegroup creation date and time
  returned: when state is present
  type: str
  sample: '2022-01-18T20:00:00.111000+00:00'
modifiedAt:
  description: Nodegroup modified date and time
  returned: when state is present
  type: str
  sample: '2022-01-18T20:00:00.111000+00:00'
status:
  description: status of the EKS Fargate Profile
  returned: when state is present
  type: str
  sample:
  - CREATING
  - ACTIVE
capacityType:
  description: The capacity type of your managed node group.
  returned: when state is present
  type: str
  sample: need_validate
scalingConfig:
  description: The scaling configuration details for the Auto Scaling group that is associated with your node group.
  returned: when state is present
  type: dict
  sample: need_validate
instanceTypes:
  description: This is the instance type that is associated with the node group.
  returned: when state is present
  type: list
  sample: need_validate
subnets:
  description: List of subnets used in Fargate Profile
  returned: when state is present
  type: list
  sample:
  - subnet-qwerty123
  - subnet-asdfg456
remoteAccess:
  description: This is the remote access configuration that is associated with the node group.
  returned: when state is present
  type: dict
  sample: need_validate
amiType:
  description: This is the AMI type that was specified in the node group configuration.
  returned: when state is present
  type: str
  sample: need_validate
nodeRole:
  description: ARN of the IAM Role used by Nodegroup
  returned: when state is present
  type: str
  sample: arn:aws:eks:us-east-1:1231231123:role/asdf
labels:
  description: The Kubernetes labels applied to the nodes in the node group.
  returned: when state is present
  type: dict
  sample: need_validate
taints:
  description: The Kubernetes taints to be applied to the nodes in the node group when they are created.
  returned: when state is present
  type: list
  sample: need_validate
resources:
  description: The resources associated with the node group.
  returned: when state is present
  type: complex
  contains:
    autoScalingGroups:
      description: The Auto Scaling groups associated with the node group.
      returned: when state is present
      type: list
      elements: dict
    remoteAccessSecurityGroup:
      description: The remote access security group associated with the node group.
      returned: when state is present
      type: str
diskSize:
  description: This is the disk size in the node group configuration.
  returned:  when state is present
  type: int
  sample: 20
health:
  description: The health status of the node group.
  returned: when state is present
  type: dict
  sample: need_validate
updateConfig:
  description: The node group update configuration.
  returned: when state is present
  type: dict
  contains:
    maxUnavailable:
      description: The maximum number of nodes unavailable at once during a version update.
      type: int
    maxUnavailablePercentage:
      description: The maximum percentage of nodes unavailable during a version update.
      type: int
lauchTemplate:
  description: If a launch template was used to create the node group, then this is the launch template that was used.
  returned: when state is present
  type: dict
  sample: need_validate
tags:
  description: Nodegroup tags
  returned: when state is present
  type: dict
  sample:
    foo: bar
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
                update_params = dict()
                update_params['clusterName'] = module.params['cluster_name'],
                update_params['nodegroupName'] = module.params.get['name'],
                update_params['scalingConfig'] = module.params['scaling_config'],
                update_params['updateConfig'] = module.params['update_config']

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
            client.delete_nodegroup(clusterName=clusterName, nodegroupName=name)
        except (botocore.exceptions.BotoCoreError, botocore.exceptions.ClientError) as e:
            module.fail_json_aws(e, msg="Couldn't delete Nodegroup %s" % name)

    if wait:
        wait_until(client, module, 'nodegroup_deleted', name, clusterName)

    module.exit_json(changed=True)


def get_nodegroup(client, module, nodegroup_name, cluster_name):
    try:
        return client.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)['nodegrouop']
    except is_boto3_error_code('ResourceNotFoundException'):
        return None


def wait_until(client, module, waiter_name, nodegroup_name, cluster_name):
    wait_timeout = module.params.get('wait_timeout')
    waiter = client.get_waiter(waiter_name)
    attempts = 1 + int(wait_timeout / waiter.config.delay)
    waiter.wait(clusterName=cluster_name, nodegroupName=nodegroup_name, WaiterConfig={'MaxAttempts': attempts})


def main():
    argument_spec = dict(
        name=dict(required=True),
        cluster_name=dict(required=True),
        node_role=dict(),
        subnets=dict(type='list', elements='str'),
        scaling_config=dict(type='dict', options=dict(
            min_size=dict(type='int'),
            max_size=dict(type='int'),
            desire_size=dict(type='int')
        )),
        disk_size=dict(type='int'),
        instance_types=dict(type='list', elements='str'),
        ami_type=dict(choices=['AL2_x86_64', 'AL2_x86_64_GPU', 'AL2_ARM_64', 'CUSTOM', 'BOTTLEROCKET_ARM_64', 'BOTTLEROCKET_x86_64']),
        remote_access=dict(type='dict', options=dict(
            ec2_ssh_key=dict(no_log=True),
            source_sg=dict(type='list', elements='str')
        )),
        update_config=dict(type='dict', options=dict(
            max_unavailable=dict(type='int'),
            max_unavailable_percentage=dict(type='int'),
        )),
        labels=dict(type='dict'),
        taints=dict(type='list', elements='dict'),
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
        required_if=[['state', 'present', ['name', 'cluster_name', 'node_role', 'subnets', 'scaling_config', 'disk_size', 'instance_types', 'ami_type']]],
        supports_check_mode=True,
    )

    client = module.client('eks')

    if module.params.get('state') == 'present':
        create_or_update_nodegroups(client, module)
    else:
        delete_nodegroups(client, module)


if __name__ == '__main__':
    main()
