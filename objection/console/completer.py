import collections

from prompt_toolkit.completion import Completer, Completion, CompleteEvent
from prompt_toolkit.document import Document

from .commands import COMMANDS
from ..utils.helpers import get_tokens


class CommandCompleter(Completer):
    """
        The objection REPL command completer.
    """

    def __init__(self) -> None:
        super(CommandCompleter, self).__init__()
        self.COMMANDS = COMMANDS

    def find_completions(self, document: Document) -> dict:
        """
            Find tab completions from the commands repository.

            Completions are returned based on tokens extracted
            from the command text received by prompt_toolkit. A
            dictionary is then walked, matching a token to a
            nested dictionary until no more dictionaries are
            available. The resultant dictionary then becomes
            the suggestions for tab completion.

            Some commands may have 'dynamic' completions, such as
            file system related commands. They are defined with a
            'dynamic' key, and the method defined as the value for
            this key is executed to get completions.

            :param document:
            :return:
        """

        # extract tokens from the document similar to
        # how a shell invocation would have been done.
        # we will also cleanup flags that come in the form
        #  of --flag so that multiples can be suggested.
        tokens = [token for token in get_tokens(document.text) if not token.startswith('--')]

        # extract the flags in the received tokens. This list
        # will be used to remove suggested flags from those
        # already present in the command.
        flags = [flag for flag in get_tokens(document.text) if flag.startswith('--')]

        # start with the current suggestions dictionary being
        # all commands
        current_suggestions = self.COMMANDS

        # when the tokens are extracted, we are expecting something in
        # the format of:
        #   command sub_command sub_sub_command
        # so, lets use that and search the the COMMAND dictionary for
        # the last dictionary with a correct suggestion
        for token in tokens:

            candidate = token.lower()

            if candidate in list(current_suggestions.keys()):

                # if there are sub commands, grab them
                if 'commands' in current_suggestions[candidate]:
                    current_suggestions = current_suggestions[candidate]['commands']

                # dynamic commands change based on the current status of the
                # environment, so, call the method defined
                elif 'dynamic' in current_suggestions[candidate]:
                    current_suggestions = current_suggestions[candidate]['dynamic']()

                # make --flags in the 'flags' key tab completable
                elif 'flags' in current_suggestions[candidate]:
                    current_suggestions = {
                        flag: '' for flag in current_suggestions[candidate]['flags'] if flag not in flags
                    }

                # in this case, there are probably no sub commands, so return
                # an empty dictionary
                else:
                    return {}

        suggestions = {}

        # once we have the deepest suggestions dictionary in the
        # current_suggestions variable, loop through and check for
        # 'sorta' matched versions
        if current_suggestions and len(current_suggestions) > 0:
            for k, _ in current_suggestions.items():

                # fuzzy-ish matching when part of a word is in a suggestion
                if document.get_word_before_cursor().lower() in k.lower():
                    suggestions[k] = current_suggestions[k]

        return suggestions

    def get_completions(self, document: Document, complete_event: CompleteEvent) -> Completion:
        """
            The main method that gets called by prompt-toolkit to
            determine which completions to show. This

            :param document:
            :param complete_event:
            :return:
        """

        commands = {}

        # get the stuff we have typed so far
        word_before_cursor = document.get_word_before_cursor()

        # get command suggestions if we are not expecting an OS command
        if not document.text.startswith('!'):
            commands.update(self.find_completions(document))

        # if there are no commands return
        if len(commands) <= 0:
            return

        # sort alphabetically
        commands = collections.OrderedDict(sorted(list(commands.items()), key=lambda t: t[0]))

        # loop the commands that we have determined to be useful
        # based on the current text input and populate a 'meta' field
        # if one exists.
        for cmd, extra in commands.items():
            meta = extra['meta'] if type(extra) is dict and 'meta' in extra else None

            # finally, yield the generator for completions
            yield Completion(cmd, -(len(word_before_cursor)), display_meta=meta)
