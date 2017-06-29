from objection.utils.frida_transport import FridaRunner
from objection.utils.templates import ios_hook


def monitor(args=None):
    hook = ios_hook('pasteboard/monitor')

    runner = FridaRunner(hook=hook)
    runner.run_as_job(name='pasteboard-monitor')
