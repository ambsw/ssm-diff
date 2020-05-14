
from __future__ import print_function

import json
import logging
import re
import sys
from copy import deepcopy
from json import JSONDecodeError

import boto3
import termcolor
import yaml
from botocore.exceptions import ClientError, NoCredentialsError

from .helpers import merge, add, filter, search


def str_presenter(dumper, data):
    if len(data.splitlines()) == 1 and data[-1] == '\n':
        return dumper.represent_scalar(
            'tag:yaml.org,2002:str', data, style='>')
    if len(data.splitlines()) > 1:
        return dumper.represent_scalar(
            'tag:yaml.org,2002:str', data, style='|')
    return dumper.represent_scalar(
        'tag:yaml.org,2002:str', data.strip())


yaml.SafeDumper.add_representer(str, str_presenter)


class SecureTag(yaml.YAMLObject):
    yaml_tag = u'!secure'
    # forward compatibility
    metadata = {}

    def __init__(self, secure):
        self.secure = secure

    def __repr__(self):
        return self.secure

    def __str__(self):
        return termcolor.colored(self.secure, 'magenta')

    def __eq__(self, other):
        return self.secure == other.secure if isinstance(other, SecureTag) else False

    def __hash__(self):
        return hash(self.secure)

    def __ne__(self, other):
        return not self.__eq__(other)

    @property
    def secret(self):
        return self.secure

    @classmethod
    def from_yaml(cls, loader, node):
        return SecureTag(node.value)

    @classmethod
    def to_yaml(cls, dumper, data):
        if len(data.secure.splitlines()) > 1:
            return dumper.represent_scalar(cls.yaml_tag, data.secure, style='|')
        return dumper.represent_scalar(cls.yaml_tag, data.secure)


class SecureString(yaml.YAMLObject):
    yaml_tag = u'!SecureString'


class Secret(yaml.YAMLObject):
    yaml_tag = u'!Secret'
    METADATA_ENCRYPTED = 'encrypted'

    def __init__(self, secret, metadata=None, encrypted=False):
        super().__init__()
        self.secret = secret
        self.metadata = {} if metadata is None else metadata
        self.metadata[self.METADATA_ENCRYPTED] = encrypted

    def __repr__(self):
        return "{}(secret={!r}, metadata={!r})".format(self.__class__.__name__, self.secret, self.metadata)

    def __eq__(self, other):
        if isinstance(other, Secret):
            return self.secret == other.secret and self.metadata == other.metadata
        if isinstance(other, SecureTag):
            return self.secret == other.secure
        return False

    @classmethod
    def from_yaml(cls, loader, node):
        node.tag = ''
        try:
            return SecretJSONBranch.from_yaml(loader, node)
        except JSONDecodeError:
            pass
        if isinstance(node, yaml.MappingNode):
            value = loader.construct_mapping(node)
            return Secret(**value)
        else:
            value = loader.construct_scalar(node)
            return Secret(value)

    @classmethod
    def to_yaml(cls, dumper, data):
        return dumper.represent_scalar(cls.yaml_tag, data.secret)


class JSONBranchEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (SecureTag, SecureString, Secret)):
            raise TypeError("Cannot nest secure value in JSONBranch; use SecureJSONBranch instead.")
        # Let the base class default method raise the TypeError
        return super().default(self, obj)


class JSONBranch(yaml.YAMLObject):
    yaml_tag = u'!JSON'
    encoder = JSONBranchEncoder
    encoded_tag = u'tag:yaml.org,2002:str'

    def __init__(self, raw):
        self.raw = raw

    def __eq__(self, other):
        return repr(self) == (repr(other) if isinstance(other, JSONBranch) else other)

    def __hash__(self):
        return hash(self.value)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __repr__(self):
        return repr(self.raw)

    def __str__(self):
        return self.value

    @property
    def value(self):
        return json.dumps(self.raw, cls=self.encoder)

    @classmethod
    def from_yaml(cls, loader, node):
        """Accept a nested YAML structure and convert it to a nested python structure."""
        assert isinstance(loader, yaml.SafeLoader)
        # ignore the top-level node
        node.tag = ''
        if isinstance(node, yaml.MappingNode):
            value = loader.construct_mapping(node)
        else:
            value = json.loads(loader.construct_scalar(node))
        return cls(value)

    @classmethod
    def to_yaml(cls, dumper, data):
        """Convert a nested python structure into a !secret containing a JSON string."""
        return dumper.represent_scalar(cls.encoded_tag, data.value)


class SecureJSONBranchEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (SecureTag, SecureString)):
            return obj.secure
        if isinstance(obj, Secret):
            return obj.secret
        # Let the base class default method raise the TypeError
        return super().default(self, obj)


class SecretJSONBranch(JSONBranch, Secret):
    yaml_tag = u'!secretJSON'
    encoder = SecureJSONBranchEncoder
    encoded_tag = Secret.yaml_tag

    def __init__(self, raw):
        super().__init__(raw)
        self.metadata = {
            self.METADATA_ENCRYPTED: False,
        }

    def __repr__(self):
        return "{}(secret={!r}, metadata={!r})".format(self.__class__.__name__, self.secret, self.metadata)

    def __eq__(self, other):
        return super().__eq__(other)

    @property
    def secret(self):
        return self.value


yaml.SafeLoader.add_constructor(SecureTag.yaml_tag, SecureTag.from_yaml)
yaml.SafeDumper.add_multi_representer(SecureTag, SecureTag.to_yaml)
# backwards compatibility
yaml.SafeLoader.add_constructor(SecureString.yaml_tag, SecureTag.from_yaml)
# yaml.SafeDumper.add_multi_representer(SecureTag, SecureTag.to_yaml)
yaml.SafeLoader.add_constructor(Secret.yaml_tag, Secret.from_yaml)
yaml.SafeDumper.add_multi_representer(Secret, Secret.to_yaml)
yaml.SafeLoader.add_constructor(JSONBranch.yaml_tag, JSONBranch.from_yaml)
yaml.SafeDumper.add_multi_representer(JSONBranch, JSONBranch.to_yaml)
yaml.SafeLoader.add_constructor(SecretJSONBranch.yaml_tag, SecretJSONBranch.from_yaml)
yaml.SafeDumper.add_multi_representer(SecretJSONBranch, SecretJSONBranch.to_yaml)


class YAMLFile(object):
    """Encodes/decodes a dictionary to/from a YAML file"""
    METADATA_CONFIG = 'ssm-diff:config'
    METADATA_PATHS = 'ssm-diff:paths'
    METADATA_ROOT = 'ssm-diff:root'
    METADATA_NO_SECURE = 'ssm-diff:no-secure'
    METADATA_NO_DECRYPT = 'ssm-diff:no-decrypt'

    def __init__(self, filename, paths=('/',), root_path='/', no_secure=False, no_decrypt=False):
        self.filename = '{}.yml'.format(filename)
        self.root_path = root_path
        self.paths = paths
        self.validate_paths()
        self.no_secure = no_secure
        self.no_decrypt = no_decrypt

    def validate_paths(self):
        length = len(self.root_path)
        for path in self.paths:
            if path[:length] != self.root_path:
                raise ValueError('Root path {} does not contain path {}'.format(self.root_path, path))

    def exists(self):
        try:
            open(self.filename, 'rb')
        except FileNotFoundError:
            return False
        return True

    def get(self):
        try:
            output = {}
            with open(self.filename, 'rb') as f:
                local = yaml.safe_load(f.read())
            self.validate_config(local)
            # nest the local at its original location
            local = self.nest_root(local)
            # extract only the relevant paths
            for path in self.paths:
                # if any path is the root_path, return everything
                if path.strip('/') == self.root_path.strip('/'):
                    return local
                else:
                    output = merge(output, filter(local, path))
            return output
        except TypeError as e:
            if 'object is not iterable' in e.args[0]:
                return dict()
            raise

    def validate_config(self, local):
        """YAML files may contain a special ssm:config tag that stores information about the file when it was generated.
        This information can be used to ensure the file is compatible with future calls.  For example, a file created
        with a particular subpath (e.g. /my/deep/path) should not be used to overwrite the root path since this would
        delete any keys not in the original scope.  This method does that validation (with permissive defaults for
        backwards compatibility)."""
        config = local.pop(self.METADATA_CONFIG, {})

        # strict requirement that the no_secure setting is equal
        config_no_secure = config.get(self.METADATA_NO_SECURE, False)
        if config_no_secure != self.no_secure:
            raise ValueError("YAML file generated with no_secure={} but current class set to no_secure={}".format(
                config_no_secure, self.no_secure,
            ))
        # only apply no_decrypt if we actually download secure
        if not self.no_secure:
            config_no_decrypt = config.get(self.METADATA_NO_DECRYPT, False)
            if config_no_decrypt != self.no_decrypt:
                raise ValueError("YAML file generated with no_decrypt={} but current class set to no_decrypt={}".format(
                    config_no_decrypt, self.no_decrypt,
                ))
        # strict requirement that root_path is equal
        config_root = config.get(self.METADATA_ROOT, '/')
        if config_root != self.root_path:
            raise ValueError("YAML file generated with root_path={} but current class set to root_path={}".format(
                config_root, self.root_path,
            ))
        # make sure all paths are subsets of file paths
        config_paths = config.get(self.METADATA_PATHS, ['/'])
        for path in self.paths:
            for config_path in config_paths:
                # if path is not found in a config path, it could look like we've deleted values
                if path[:len(config_path)] == config_path:
                    break
            else:
                raise ValueError("Path {} was not included in this file when it was created.".format(path))

    def unnest_root(self, state):
        if self.root_path == '/':
            return state
        return search(state, self.root_path)

    def nest_root(self, state):
        if self.root_path == '/':
            return state
        return add({}, self.root_path, state)

    def save(self, state):
        state = self.unnest_root(state)
        # inject state information so we can validate the file on load
        # colon is not allowed in SSM keys so this namespace cannot collide with keys at any depth
        state[self.METADATA_CONFIG] = {
            self.METADATA_PATHS: self.paths,
            self.METADATA_ROOT: self.root_path,
            self.METADATA_NO_SECURE: self.no_secure
        }
        try:
            with open(self.filename, 'wb') as f:
                content = yaml.safe_dump(state, default_flow_style=False)
                f.write(bytes(content.encode('utf-8')))
        except Exception as e:
            print(e, file=sys.stderr)
            sys.exit(1)


class ParameterStore(object):
    """Encodes/decodes a dict to/from the SSM Parameter Store"""
    invalid_characters = r'[^a-zA-Z0-9\-_\./]'
    KMS_KEY = 'aws:kms:alias'

    def __init__(self, profile, diff_class, paths=('/',), no_secure=False, no_decrypt=False):
        self.logger = logging.getLogger(self.__class__.__name__)
        # lazy loaded to simplify testing
        # TODO: convert to injection
        self.profile = profile
        self._ssm = None
        self.diff_class = diff_class
        self.paths = paths
        self.parameter_filters = []
        if no_secure:
            self.parameter_filters.append({
                'Key': 'Type',
                'Option': 'Equals',
                'Values': [
                    'String', 'StringList',
                ]
            })
        self.no_decrypt = no_decrypt

    @property
    def ssm(self):
        """Lazy loaded to simplify testing"""
        if self._ssm is None:
            if self.profile:
                boto3.setup_default_session(profile_name=self.profile)
            self._ssm = boto3.client('ssm')
        return self._ssm

    def _enrich_metadata(self, params):
        ss_params = [ k for k, v in params.items() if v["Type"] == "SecureString" ]
        p = self.ssm.get_paginator('describe_parameters')
        chunk_size = 50
        for i in range(0, len(ss_params), chunk_size):
            for page in p.paginate(ParameterFilters=[{'Key': 'Name', 'Values': ss_params[i:i+chunk_size]}]):
                for param in page['Parameters']:
                    params[param['Name']]['KeyId'] = param['KeyId']
        return params

    def clone(self):
        p = self.ssm.get_paginator('get_parameters_by_path')
        output = {}
        params = {}
        try:
            for path in self.paths:
                for page in p.paginate(
                    Path=path,
                    Recursive=True,
                    WithDecryption=not self.no_decrypt,
                    ParameterFilters=self.parameter_filters,
                ):
                    for param in page['Parameters']:
                        params[param['Name']] = {'Value': param['Value'], 'Type': param['Type']}
            params = self._enrich_metadata(params)
            for param_name, param_obj in params.items():
                args = {'value': param_obj['Value'], 'ssm_type': param_obj['Type'], 'name': param_name }
                if 'KeyId' in param_obj:
                    args['key_id'] = param_obj['KeyId']
                add(obj=output,
                    path=param_name,
                    value=self._read_param(**args))
        except (ClientError, NoCredentialsError) as e:
            print("Failed to fetch parameters from SSM!", e, file=sys.stderr)

        return output

    # noinspection PyMethodMayBeStatic
    def _read_param(self, value, ssm_type='String', name=None, key_id=None):
        if ssm_type == 'SecureString':
            value = Secret(value, {
                self.KMS_KEY: key_id,
            }, encrypted=self.no_decrypt)
        elif ssm_type == 'StringList':
            value = value.split(',')
        return value

    def pull(self, local):
        diff = self.diff_class(
            remote=self.clone(),
            local=local,
        )
        return diff.merge()

    @classmethod
    def coerce_state(cls, state, path='/', sep='/'):
        errors = {}
        for k, v in state.items():
            if re.search(cls.invalid_characters, k) is not None:
                errors[path+sep+k]: 'Invalid Key'
                continue
            if isinstance(v, dict):
                errors.update(cls.coerce_state(v, path=path + sep + k))
            elif isinstance(v, list):
                list_errors = []
                for item in v:
                    if not isinstance(item, str):
                        list_errors.append('list items must be strings: {}'.format(repr(item)))
                    elif re.search(r'[,]', item) is not None:
                        list_errors.append("StringList is comma separated so items may not contain commas: {}".format(item))
                if list_errors:
                    errors[path+sep+k] = list_errors
            elif isinstance(v, (str, SecureTag, Secret)):
                continue
            elif isinstance(v, JSONBranch):
                continue
            elif isinstance(v, (int, float)):
                state[k] = str(v)
            elif isinstance(v, type(None)):
                state[k] = None
            else:
                errors[path+sep+k] = 'Cannot coerce type {}'.format(type(v))
        return errors

    def dry_run(self, local):
        working = deepcopy(local)
        errors = self.coerce_state(working)
        if errors:
            raise ValueError('Errors during dry run:\n{}'.format(errors))
        plan = self.diff_class(self.clone(), working).plan
        plan = self.reclassify_none_as_absent(plan)
        return plan

    def reclassify_none_as_absent(self, plan):
        """Parameter store has no concept of "None" and does not accept empty strings so we must treat None as an
        absent key.  This method alters the plan accordingly."""
        relocate = []
        for k, v in plan['add'].items():
            if v is None:
                relocate.append(k)
        for k in relocate:
            del plan['add'][k]
        relocate = []
        for k, v in plan['change'].items():
            if v['new'] is None:
                relocate.append(k)
        for k in relocate:
            plan['delete'][k] = plan['change'][k]['old']
            del plan['change'][k]

        return plan

    def prepare_param(self, name, value):
        # semantically, delete is probably better but this should have similar consequences without creating exceptions
        if value is None:
            value = ''
        kwargs = {
            'Name': name,
        }
        if isinstance(value, list):
            kwargs['Type'] = 'StringList'
            kwargs['Value'] = ','.join(value)
        elif isinstance(value, (Secret, SecureTag)):
            kwargs['Type'] = 'SecureString'
            kwargs['Value'] = value.secret
            if self.KMS_KEY in value.metadata:
                kwargs['KeyId'] = value.metadata[self.KMS_KEY]
        else:
            kwargs['Type'] = 'String'
            kwargs['Value'] = str(value)
        return kwargs

    def push(self, local):
        plan = self.dry_run(local)

        for k, v in plan['add'].items():
            # { key: new_value }
            self.logger.info('add: {}'.format(k))
            kwargs = self.prepare_param(k, v)
            self.ssm.put_parameter(**kwargs)

        for k, delta in plan['change'].items():
            # { key: {'old': value, 'new': value} }
            self.logger.info('change: {}'.format(k))
            kwargs = self.prepare_param(k, delta['new'])
            kwargs['Overwrite'] = True
            self.ssm.put_parameter(**kwargs)

        for k in plan['delete']:
            # { key: old_value }
            self.logger.info('delete: {}'.format(k))
            self.ssm.delete_parameter(Name=k)
