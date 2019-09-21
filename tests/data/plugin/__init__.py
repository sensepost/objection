__description__ = "An example plugin, also used in a UnitTest"

from objection.utils.plugin import Plugin

s = """
rpc.exports = {
    getInformation: function() {
        console.log('hello from Frida');    // direct output
        send('Incoming message');           // output via send for 'message' signal
        return Frida.version;               // return type
    }
}
"""


class VersionInfo(Plugin):
    """ VersionInfo is a sample plugin to get Frida version information """

    def __init__(self, ns):
        """
            Creates a new instance of the plugin

            :param ns:
        """

        self.script_src = s
        # self.script_path = os.path.join(os.path.dirname(__file__), "script.js")

        implementation = {
            'meta': 'Work with Frida version information',
            'commands': {
                'info': {
                    'meta': 'Get the current Frida version',
                    'exec': self.version
                }
            }
        }

        super().__init__(__file__, ns, implementation)

        self.inject()

    def version(self, args: list):
        """
            Tests a plugin by calling an RPC export method
            called getInformation, and printing the result.

            :param args:
            :return:
        """

        v = self.api.get_information()
        print('Frida version: {0}'.format(v))


namespace = 'version'
plugin = VersionInfo
