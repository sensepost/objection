import collections

from prompt_toolkit.completion import Completer, Completion

from .repository import COMMANDS
from ..utils.helpers import get_tokens


class CommandCompleter(Completer):
    """
        The command completer
    """

    def __init__(self):
        super(CommandCompleter, self).__init__()
        self.COMMANDS = COMMANDS

    def find_completions(self, document):

        # extract tokens from the docment similar to
        # how a shell invokation would have been done
        tokens = get_tokens(document.text)

        # start with the current suggestions dictionary being
        # root commands
        current_suggestions = self.COMMANDS['commands']

        # when the tokens are extracted, we are expecting something in
        # the format of:
        #   command sub_command sub_sub_command
        # so, lets use that and serach the the COMMAND dictionary for
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

                # in this case, there are probably no sub commands, so return
                # an empty dictionary
                else:
                    return {}

        suggestions = {}

        # once we have the deepest suggestions ictionary in the
        # current_suggestions variable, loop through and check for
        # 'sorta' matched versions
        if current_suggestions and len(current_suggestions) > 0:
            for k, _ in current_suggestions.items():
                if document.get_word_before_cursor().lower() in k.lower():
                    suggestions[k] = current_suggestions[k]

        return suggestions

    def get_completions(self, document, complete_event):
        """
            The main method that gets called by prompt-toolkit to
            determine which completions to show.

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

        # if there are commands, show them
        if len(commands) > 0:

            # sort alphabetically
            commands = collections.OrderedDict(sorted(list(commands.items()), key=lambda t: t[0]))

            for cmd, extra in commands.items():
                meta = extra['meta'] if 'meta' in extra else None
                yield Completion(cmd, -(len(word_before_cursor)), display_meta=meta)
