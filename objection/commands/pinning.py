from objection.utils.frida_transport import FridaRunner
from objection.utils.templates import ios_hook


def ios_disable(args=None):
    hook = ios_hook('pinning/disable')

    runner = FridaRunner(hook=hook)
    runner.run_as_job(name='pinning-disable')
