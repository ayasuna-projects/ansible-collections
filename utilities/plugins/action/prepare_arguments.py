import copy
import hashlib
import importlib.util
import json
from json import JSONEncoder
from typing import List, Any

from ansible.errors import AnsibleError, AnsibleActionFail
from ansible.module_utils.common.arg_spec import ArgumentSpecValidator
from ansible.module_utils.common.text.converters import to_text
from ansible.parsing.yaml.objects import AnsibleVaultEncryptedUnicode
from ansible.plugins.action import ActionBase
from ansible.template import Templar
from ansible.template import trust_as_template


class _JSONEncoder(JSONEncoder):

    def default(self, o):
        if isinstance(o, AnsibleVaultEncryptedUnicode):
            return o.data

        return super().default(o)


class _DefaultValue:
    """
    Represents a default value
    """

    def __init__(self, value: Any, keep: bool):
        """
        Creates a new ``_DefaultValue`` which wraps the given ``value``.
        
        :param value: The value to wrap
        :param keep: Whether to keep the value even if it is None
        """

        self.value = value
        self.keep = keep


class _PreparationResult:
    """
    Represents the result of an argument preparation
    """

    def __init__(self, errors: List[str], arguments: dict[str, Any]):
        """
        Creates a new ``_PreparationResult``
        
        :param errors: The errors that occurred while preparing the arguments
        :param arguments: The actual prepared arguments
        """

        self.errors = errors
        self.arguments = arguments


class _Preparer:
    """
    Represents an argument preparer
    """

    def prepare(self, arguments: dict) -> _PreparationResult:
        """
        Prepares the given ``arguments``
        
         :return _PreparationResult: The preparation result
        """
        raise NotImplementedError("The prepare method must be implemented")


class _NoopBasedPreparer(_Preparer):
    """
    Preparer implementation that does nothing
    """

    def prepare(self, arguments: dict) -> _PreparationResult:
        return _PreparationResult([], arguments)


class _ModuleBasedPreparer(_Preparer):
    """
    Preparer implementation that uses the 'convert' and 'validate' functions of a specific module
    """

    def __init__(self, module):
        self._module = module

    def prepare(self, arguments: dict) -> _PreparationResult:

        if hasattr(self._module, "validate"):
            errors = self._module.validate(arguments)

            if len(errors) > 0:
                return _PreparationResult(errors, {})

        if hasattr(self._module, "convert"):
            return _PreparationResult([], self._module.convert(arguments))

        return _PreparationResult([], arguments)


class _InitialPreparer(_Preparer):
    """
    Represents the first preparer that is run
    """

    def __init__(self, templar: Templar, argument_spec_options: dict[str, Any], prefixes: list[str]):
        """
        Creates a new ``_InitialPreparer`` which prepares arguments by:
        
        - First normalizing them
        - Then validating them against the given ``argument_spec_options`` via an ``ArgumentSpecValidator``
        - Afterward, removing all characters until after the last "__" from all keys
        - Finally, performing the validation rules defined by the ``argument_spec_options``
        
        :param templar: The templar to use to evaluate the custom validation rule expressions
        :param argument_spec_options: The argument specification options
        :param prefixes: The prefixes
        """
        self._templar = templar
        self._validator = ArgumentSpecValidator(argument_spec_options)
        self._prefixes = prefixes

    def prepare(self, arguments: dict) -> _PreparationResult:

        validation_result = self._validator.validate(arguments, validate_role_argument_spec=True)

        if validation_result.error_messages:
            return _PreparationResult(validation_result.error_messages, {})

        prepared_arguments = {}

        for key, value in arguments.items():
            
            matching_prefix = None
            for prefix in self._prefixes:
                if key.startswith(prefix):
                    matching_prefix = prefix
                    break

            if matching_prefix is None:
                prepared_arguments[key] = copy.deepcopy(value)
            else:
                prepared_arguments[key[len(matching_prefix):]] = copy.deepcopy(value)
            
        validate_rules_result = self._validate_rules(prepared_arguments, self._validator.argument_spec, [])

        return _PreparationResult(validate_rules_result, prepared_arguments)

    def _validate_rules(self, arguments: dict[str, Any], argument_spec_options: dict[str, Any], indices: list[int]) -> List[str]:
        """
        Validates the custom rules provided in the 'context' field of a parameter
        """

        result = []

        for argument_spec_option_key, argument_spec_option in argument_spec_options.items():

            # If the argument_spec_option_key is not part of 'arguments'
            # we know the parameter is not required so no validation is necessary
            if argument_spec_option_key in arguments:

                current_argument = arguments[argument_spec_option_key]

                if "context" in argument_spec_option and "rules" in argument_spec_option["context"] and len(argument_spec_option["context"]["rules"]) > 0:

                    for rule in argument_spec_option["context"]["rules"]:

                        if "expression" not in rule or "message" not in rule:
                            result.append(
                                f"Rule for '{argument_spec_option_key}' is missing 'message' and/or 'expression' field"
                            )
                            continue
                        try:
                            expression_result = self._templar.evaluate_expression(trust_as_template(rule["expression"]),
                                                                                  local_variables={
                                                                                      "indices": indices,
                                                                                      "arguments": arguments
                                                                                  },
                                                                                  escape_backslashes=True)

                            if not isinstance(expression_result, bool):
                                result.append(
                                    f"Rule with expression '{rule['expression']}' did not result in a bool "
                                    f"but instead resulted in '{expression_result}'"
                                )
                            elif not expression_result:
                                result.append(rule["message"])

                        except AnsibleError as e:
                            result.append(
                                f"Rule with expression '{rule['expression']}' "
                                f"could not be evaluated because {e}"
                            )

                argument_spec_option_is_dict = argument_spec_option["type"] == "dict"
                argument_spec_option_is_list_of_dicts = (argument_spec_option["type"] == "list" and
                                                         "elements" in argument_spec_option and
                                                         argument_spec_option["elements"] == "dict")

                # An 'options' field is only valid/expected for (sub-)specs of type 'dict' and 'list'
                if "options" in argument_spec_option and (argument_spec_option_is_dict or argument_spec_option_is_list_of_dicts):

                    if argument_spec_option_is_list_of_dicts:

                        # Special case the list itself *might* be None which is not iterable
                        if current_argument is not None:
                            for index, current_argument_element in enumerate(current_argument):
                                new_indices = indices.copy()
                                new_indices.append(index)

                                result.extend(self._validate_rules(current_argument_element, argument_spec_option["options"], new_indices))

                    else:
                        result.extend(self._validate_rules(current_argument, argument_spec_option["options"], indices))

        return result


class ActionModule(ActionBase):
    """Prepares arguments"""

    def run(self, tmp=None, task_vars=None or dict):
        if task_vars is None:
            task_vars = {}

        super(ActionModule, self).run(tmp, task_vars)

        argument_spec = self._task.args.get("specification")

        preparers = self._get_preparers(argument_spec)
        prepared_arguments: dict = self._get_arguments(self._get_argument_spec_options(argument_spec), task_vars)

        for preparer in preparers:

            preparation_result = preparer.prepare(prepared_arguments)

            if len(preparation_result.errors) > 0:
                return {
                    "changed": False,
                    "failed": True,
                    "errors": preparation_result.errors,
                    "msg": ("Failed to prepare the given arguments due to: \n" +
                            "\n".join(preparation_result.errors))
                }

            prepared_arguments = preparation_result.arguments

        return {
            "changed": False,
            "specification": argument_spec,
            "prepared": prepared_arguments,
            "hash": hashlib.md5(
                json.dumps(prepared_arguments, sort_keys=True, ensure_ascii=True, cls=_JSONEncoder).encode("utf-8")
            ).hexdigest(),
            "msg": "Successfully prepared the given arguments with the given argument_spec"
        }

    def _get_preparers(self, argument_spec: dict[str, Any]) -> List[_Preparer]:
        """
        Gets the preparers
        
        :param argument_spec: The argument specification
        
        :return: The preparers
        """
        argument_spec_options = self._get_argument_spec_options(argument_spec)
        prefixes = argument_spec["context"]["prefixes"] if "context" in argument_spec and "prefixes" in argument_spec["context"] else []
        preparer = argument_spec["context"]["preparer"] if "context" in argument_spec and "preparer" in argument_spec["context"] else None

        return [
            _InitialPreparer(
                self._templar.copy_with_new_env(available_variables={}),
                argument_spec_options,
                prefixes
            ),
            self._get_preparer(preparer)
        ]

    def _get_preparer(self, preparer: str | None) -> _Preparer:
        """
        Creates a new ``_Preparer``
        
        :param preparer:    The python code backing the preparer.
                            May define two functions:
                            - validate(arguments: dict[str, Any]) -> list[str]
                            - convert(arguments: dict[str, Any]) -> dict[str, Any]

        :return: The preparer
        """
        
        if preparer is None or len(preparer) == 0:
            return _NoopBasedPreparer()

        preparer_hash = hashlib.sha3_512(preparer.encode("utf-8")).hexdigest()
        preparer_module_name = f"ayasuna_utilities_prepare_arguments__preparer__{preparer_hash}"
        
        preparer_module_spec = importlib.util.spec_from_loader(preparer_module_name, loader=None)
        preparer_module = importlib.util.module_from_spec(preparer_module_spec)
        
        exec(preparer, preparer_module.__dict__)

        self._display.debug(
            f"Successfully created new module with name '{preparer_module_name}'. "
            f"Creating the preparer that is backed by the module next"
        )

        return _ModuleBasedPreparer(preparer_module)

    def _get_arguments(self, argument_spec_options: dict[str, Any], variables: dict[str, Any]) -> dict[str, Any]:
        """
        Gets the arguments that are defined in the given ``argument_spec_options`` from the given ``variables``

        :param argument_spec_options: The argument specification options,
        must be compatible with https://docs.ansible.com/ansible/latest/dev_guide/developing_program_flow_modules.html#argument-spec 
        :param variables: The variables to get the arguments from
        :return The arguments
        """

        result = {}

        for argument_spec_option_key, argument_spec_option in argument_spec_options.items():
            if argument_spec_option_key in variables:

                # We have to resolve any potential variable template here to make sure we're seeing the correct value
                argument = self._templar.template(variables[argument_spec_option_key])

                if argument_spec_option["type"] == "dict":

                    if "options" in argument_spec_option:
                        result[argument_spec_option_key] = self._get_arguments(argument_spec_option["options"], argument)
                    else:
                        result[argument_spec_option_key] = argument

                elif argument_spec_option["type"] == "list" and "elements" in argument_spec_option and argument_spec_option["elements"] == "dict":

                    # Only iterate over the argument if it is a list, if it is not a list we expect
                    # the actual argument validation to fail anyway so we just use the argument as-is
                    if "options" in argument_spec_option and isinstance(argument, list):
                        inner_result = []

                        for inner_argument in argument:
                            inner_result.append(self._get_arguments(argument_spec_option["options"], inner_argument))

                        result[argument_spec_option_key] = inner_result
                    else:
                        result[argument_spec_option_key] = argument
                else:
                    result[argument_spec_option_key] = argument
            else:
                default_value = self._get_default_value(argument_spec_option)

                if default_value.keep:
                    result[argument_spec_option_key] = default_value.value

        return result

    def _get_default_value(self, argument_spec_option: dict[str, Any]) -> _DefaultValue:
        """
        Gets the default value of the given ``arg_spec_option``.
        
        :param argument_spec_option: The argument specification option
        :return The default value
        """

        if "default" in argument_spec_option:
            return _DefaultValue(argument_spec_option["default"], True)
        elif argument_spec_option["type"] == "dict" and "apply_defaults" in argument_spec_option and argument_spec_option["apply_defaults"]:
            if "options" in argument_spec_option:
                result = {}

                for inner_argument_spec_option_key, inner_argument_spec_option in argument_spec_option["options"].items():

                    default_value = self._get_default_value(inner_argument_spec_option)

                    if default_value.keep:
                        result[inner_argument_spec_option_key] = default_value.value

                return _DefaultValue(result, True)

        return _DefaultValue(None, False)
    
    @staticmethod
    def _get_argument_spec_options(argument_spec: dict[str, Any]):
        """
        Gets the argument specification options from the given ``argument_spec``
        
        :param argument_spec: The argument specification
        :return: The argument specification options
        """
        
        return argument_spec["options"] if "options" in argument_spec else {}
