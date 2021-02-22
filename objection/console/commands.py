from objection.commands import http
from ..commands import command_history
from ..commands import custom
from ..commands import device
from ..commands import filemanager
from ..commands import frida_commands
from ..commands import jobs
from ..commands import memory
from ..commands import plugin_manager
from ..commands import sqlite
from ..commands import ui
from ..commands.android import clipboard
from ..commands.android import command
from ..commands.android import general
from ..commands.android import generate as android_generate
from ..commands.android import heap as android_heap
from ..commands.android import hooking as android_hooking
from ..commands.android import intents
from ..commands.android import keystore
from ..commands.android import pinning as android_pinning
from ..commands.android import proxy as android_proxy
from ..commands.android import root
from ..commands.ios import binary
from ..commands.ios import bundles
from ..commands.ios import cookies
from ..commands.ios import generate as ios_generate
from ..commands.ios import heap as ios_heap
from ..commands.ios import hooking as ios_hooking
from ..commands.ios import jailbreak
from ..commands.ios import keychain
from ..commands.ios import monitor as ios_crypto
from ..commands.ios import nsurlcredentialstorage
from ..commands.ios import nsuserdefaults
from ..commands.ios import pasteboard
from ..commands.ios import pinning as ios_pinning
from ..commands.ios import plist
from ..utils.helpers import list_current_jobs

# commands are defined with their name being the key, then optionally
# have a meta, dynamic and commands key.

# meta: A small one-liner containing information about the command itself
# dynamic: A method to execute that would return completions to populate in the prompt
# exec: The *actual* method to execute when the command is issued.

# commands help is stored in the help files directory as a txt file.

COMMANDS = {

    'plugin': {
        'meta': 'Work with plugins',
        'commands': {
            'load': {
                'meta': 'Load a plugin',
                'exec': plugin_manager.load_plugin
            }
        }
    },

    '!': {
        'meta': 'Execute an Operating System command',
        'exec': None,  # handled in the Repl class itself
    },

    'reconnect': {
        'meta': 'Reconnect to the current device',
        'exec': None,  # handled in the Repl class itself
    },

    'import': {
        'meta': 'Import fridascript from a full path and run it',
        'exec': frida_commands.load_background
    },

    'ping': {
        'meta': 'Ping the injected agent',
        'exec': frida_commands.ping
    },

    # file manager commands

    'cd': {
        'meta': 'Change the current working directory',
        'dynamic': filemanager.list_folders_in_current_fm_directory,
        'exec': filemanager.cd
    },

    'commands': {
        'meta': 'Work with commands run in the current session',
        'commands': {
            'history': {
                'meta': 'List all unique commands that have run for this session',
                'exec': command_history.history,
            },
            'save': {
                'meta': 'Save all unique commands that have run in this session to a file',
                'exec': command_history.save
            },
            'clear': {
                'meta': 'Clear the current sessions command history',
                'exec': command_history.clear
            }
        }
    },

    'ls': {
        'meta': 'List files in the current working directory',
        'dynamic': filemanager.list_folders_in_current_fm_directory,
        'exec': filemanager.ls,
    },

    'pwd': {
        'meta': 'Print the current working directory on the device',
        'exec': filemanager.pwd_print,
    },

    'file': {
        'meta': 'Work with files on the remote filesystem',
        'commands': {
            'cat': {
                'meta': 'Print a files contents',
                'dynamic': filemanager.list_files_in_current_fm_directory,
                'exec': filemanager.cat
            },
            'upload': {
                'meta': 'Upload a file',
                'exec': filemanager.upload
            },
            'download': {
                'meta': 'Download a file',
                'dynamic': filemanager.list_files_in_current_fm_directory,
                'exec': filemanager.download
            },

            # http file server

            'http': {
                'meta': 'Work with an on device HTTP file server',
                'commands': {
                    'start': {
                        'meta': 'Start\'s an HTTP server in the current working directory',
                        'exec': http.start
                    },
                    'status': {
                        'meta': 'Get the status of the HTTP server',
                        'exec': http.status
                    },
                    'stop': {
                        'meta': 'Stop\'s a running HTTP server',
                        'exec': http.stop
                    }
                }
            },
        }
    },

    'rm': {
        'meta': 'Delete files from the remote filesystem',
        'dynamic': filemanager.list_files_in_current_fm_directory,
        'exec': filemanager.rm
    },

    # device and env info commands

    'env': {
        'meta': 'Print information about the environment',
        'exec': device.get_environment
    },

    'frida': {
        'meta': 'Get information about the Frida environment',
        'exec': frida_commands.frida_environment
    },

    'evaluate': {
        'meta': 'Evaluate JavaScript within the agent',
        'exec': custom.evaluate
    },

    # memory commands

    'memory': {
        'meta': 'Work with the current processes memory',
        'commands': {
            'dump': {
                'meta': 'Commands to dump parts of the processes memory',
                'commands': {
                    'all': {
                        'meta': 'Dump the entire memory of the current process',
                        'exec': memory.dump_all
                    },

                    'from_base': {
                        'meta': 'Dump (x) bytes of memory from a base address to file',
                        'exec': memory.dump_from_base
                    }
                },
            },

            'list': {
                'meta': 'List memory related information about the current process',
                'commands': {
                    'modules': {
                        'meta': 'List loaded modules in the current process',
                        'flags': ['--json'],
                        'exec': memory.list_modules
                    },

                    'exports': {
                        'meta': 'List the exports of a module',
                        'flags': ['--json'],
                        'exec': memory.list_exports
                    }
                },
            },

            'search': {
                'meta': 'Search for pattern in the applications memory',
                'flags': ['--string', '--offsets-only'],
                'exec': memory.find_pattern
            },

            'write': {
                'meta': 'Write raw bytes to a memory address. Use with caution!',
                'flags': ['--string'],
                'exec': memory.write
            }
        },
    },

    # sqlite commands

    'sqlite': {
        'meta': 'Work with SQLite databases',
        'commands': {
            'connect': {
                'meta': 'Connect to a SQLite database file',
                'flags': ['--sync'],
                'dynamic': filemanager.list_files_in_current_fm_directory,
                'exec': sqlite.connect
            },
        }
    },

    # jobs commands

    'jobs': {
        'meta': 'Work with objection jobs',
        'commands': {
            'list': {
                'meta': 'List all of the current jobs',
                'exec': jobs.show
            },
            'kill': {
                'meta': 'Kill a job. This unloads the script',
                'dynamic': list_current_jobs,
                'exec': jobs.kill
            }
        }
    },

    # generic ui commands

    'ui': {
        'meta': 'Generic user interface commands',
        'commands': {
            'alert': {
                'meta': 'Show an alert message, optionally specifying the message to show. (Currently crashes iOS)',
                'exec': ui.alert
            }
        }
    },

    # android commands

    'android': {
        'meta': 'Commands specific to Android',
        'commands': {
            'deoptimize': {
                'meta': 'Force the VM to execute everything in the interpreter',
                'exec': general.deoptimise
            },
            'shell_exec': {
                'meta': 'Execute a shell command',
                'exec': command.execute
            },
            'hooking': {
                'meta': 'Commands used for hooking methods in Android',
                'commands': {
                    'list': {
                        'meta': 'Lists various bits of information',
                        'commands': {
                            'classes': {
                                'meta': 'List the currently loaded classes',
                                'exec': android_hooking.show_android_classes
                            },
                            'class_methods': {
                                'meta': 'List the methods available on a class',
                                'exec': android_hooking.show_android_class_methods
                            },
                            'class_loaders': {
                                'meta': 'List the registered class loaders',
                                'exec': android_hooking.show_android_class_loaders
                            },
                            'activities': {
                                'meta': 'List the registered Activities',
                                'exec': android_hooking.show_registered_activities
                            },
                            'receivers': {
                                'meta': 'List the registered BroadcastReceivers',
                                'exec': android_hooking.show_registered_broadcast_receivers
                            },
                            'services': {
                                'meta': 'List the registered Services',
                                'exec': android_hooking.show_registered_services
                            },
                        }
                    },
                    'watch': {
                        'meta': 'Watch for Android Java invocations',
                        'commands': {
                            'class': {
                                'meta': 'Watches for invocations of all methods in a class',
                                'flags': ['--dump-args', '--dump-backtrace', '--dump-return'],
                                'exec': android_hooking.watch_class,
                            },
                            'class_method': {
                                'meta': 'Watches for invocations of a specific class method',
                                'flags': ['--dump-args', '--dump-backtrace', '--dump-return'],
                                'exec': android_hooking.watch_class_method
                            }
                        }
                    },
                    'set': {
                        'meta': 'Set various values',
                        'commands': {
                            'return_value': {
                                'meta': 'Set a methods return value. Supports only boolean returns.',
                                'exec': android_hooking.set_method_return_value
                            }
                        }
                    },
                    'get': {
                        'meta': 'Get various values',
                        'commands': {
                            'current_activity': {
                                'meta': 'Get the currently foregrounded activity',
                                'exec': android_hooking.get_current_activity
                            }
                        }
                    },
                    'search': {
                        'meta': 'Search for various classes and or methods',
                        'commands': {
                            'classes': {
                                'meta': 'Search for Java classes matching a name',
                                'exec': android_hooking.search_class
                            },
                            'methods': {
                                'meta': 'Search for Java methods matching a name',
                                'exec': android_hooking.search_methods
                            }
                        }
                    },
                    'generate': {
                        'meta': 'Generate Frida hooks for Android',
                        'commands': {
                            'class': {
                                'meta': 'A generic hook manager for Classes',
                                'exec': android_generate.clazz
                            },
                            'simple': {
                                'meta': 'Simple hooks for each Class method',
                                'exec': android_generate.simple
                            }
                        }
                    }
                },
            },
            'heap': {
                'meta': 'Commands to work with the Android Heap',
                'commands': {
                    'search': {
                        'meta': 'Search for information about the current Android heap',
                        'commands': {
                            'instances': {
                                'meta': 'Search for live instances of a particular class',
                                'exec': android_heap.instances

                            }
                        }
                    },
                    'print': {
                        'meta': 'Print information about objects on the iOS heap',
                        'commands': {
                            'fields': {
                                'meta': 'Print instance fields for a Java object handle',
                                'exec': android_heap.fields
                            },
                            'methods': {
                                'meta': 'Print instance methods for an Android handle',
                                'flags': ['--without-arguments'],
                                'exec': android_heap.methods
                            }
                        }
                    },
                    'execute': {
                        'meta': 'Execute methods on Java class handles',
                        'flags': ['--return-string'],
                        'exec': android_heap.execute
                    },
                    'evaluate': {
                        'meta': 'Evaluate JavaScript on Java class handle',
                        'exec': android_heap.evaluate
                    }
                }
            },
            'keystore': {
                'meta': 'Commands to work with the Android KeyStore',
                'commands': {
                    'list': {
                        'meta': 'Lists entries in the Android KeyStore',
                        'exec': keystore.entries
                    },
                    'clear': {
                        'meta': 'Clears the Android KeyStore',
                        'exec': keystore.clear
                    },
                    'watch': {
                        'meta': 'Watches usage of the Android keystore',
                        'exec': keystore.watch
                    }
                }
            },
            'clipboard': {
                'meta': 'Work with the Android Clipboard',
                'commands': {
                    'monitor': {
                        'meta': 'Monitor the Android Clipboard',
                        'exec': clipboard.monitor
                    }
                }
            },
            'intent': {
                'meta': 'Commands to work with Android intents',
                'commands': {
                    'launch_activity': {
                        'meta': 'Launch an Activity class using an Intent',
                        'exec': intents.launch_activity
                    },
                    'launch_service': {
                        'meta': 'Launch a Service class using an Intent',
                        'exec': intents.launch_service
                    }
                }
            },
            'root': {
                'meta': 'Commands to work with Android root detection',
                'commands': {
                    'disable': {
                        'meta': 'Attempt to disable root detection',
                        'exec': root.disable
                    },
                    'simulate': {
                        'meta': 'Attempt to simulate a rooted environment',
                        'exec': root.simulate
                    }
                }
            },
            'sslpinning': {
                'meta': 'Work with Android SSL pinning',
                'commands': {
                    'disable': {
                        'meta': 'Attempt to disable SSL pinning in various Java libraries/classes',
                        'flags': ['--quiet'],
                        'exec': android_pinning.android_disable
                    }
                }
            },
            'proxy': {
                'meta': 'Commands to work with a proxy for the application',
                'commands': {
                    'set': {
                        'meta': 'Set a proxy for the application',
                        'exec': android_proxy.android_proxy_set
                    }
                }
            },
            'ui': {
                'meta': 'Android user interface commands',
                'commands': {
                    'screenshot': {
                        'meta': 'Screenshot the current Activity',
                        'exec': ui.android_screenshot
                    },
                    'FLAG_SECURE': {
                        'meta': 'Control FLAG_SECURE of the current Activity',
                        'exec': ui.android_flag_secure
                    },
                }
            },
        },
    },

    # ios commands
    'ios': {
        'meta': 'Commands specific to iOS',
        'commands': {
            'info': {
                'meta': 'Get iOS and application related information',
                'commands': {
                    'binary': {
                        'meta': 'Get information about application binaries and dylibs',
                        'exec': binary.info
                    }
                }
            },
            'keychain': {
                'meta': 'Work with the iOS keychain',
                'commands': {
                    'dump': {
                        'meta': 'Dump the keychain for the current app\'s entitlement group',
                        'flags': ['--json', '--smart'],
                        'exec': keychain.dump
                    },
                    'dump_raw': {
                        'meta': 'Dump raw, unprocessed keychain entries (advanced)',
                        'exec': keychain.dump_raw
                    },
                    'clear': {
                        'meta': 'Delete all keychain entries for the current app\'s entitlement group',
                        'exec': keychain.clear
                    },
                    'add': {
                        'meta': 'Add an entry to the iOS keychain',
                        'flags': ['--account', '--service', '--data'],
                        'exec': keychain.add
                    }
                }
            },
            'plist': {
                'meta': 'Work with iOS Plists',
                'commands': {
                    'cat': {
                        'meta': 'Cat a plist',
                        'dynamic': filemanager.list_files_in_current_fm_directory,
                        'exec': plist.cat
                    }
                }
            },
            'bundles': {
                'meta': 'Work with iOS Bundles',
                'commands': {
                    'list_frameworks': {
                        'meta': 'Lists all of the application\'s bundles that represent frameworks',
                        'flags': ['--include-apple-frameworks', '--full-path'],
                        'exec': bundles.show_frameworks
                    },
                    'list_bundles': {
                        'meta': 'Lists all of the application\'s non framework bundles',
                        'flags': ['--full-path'],
                        'exec': bundles.show_bundles
                    }
                }
            },
            'nsuserdefaults': {
                'meta': 'Work with NSUserDefaults',
                'commands': {
                    'get': {
                        'meta': 'Get all of the entries',
                        'exec': nsuserdefaults.get
                    }
                }
            },
            'nsurlcredentialstorage': {
                'meta': 'Work with the shared NSURLCredentialStorage',
                'commands': {
                    'dump': {
                        'meta': 'Dump all of the credentials in the shared NSURLCredentialStorage',
                        'exec': nsurlcredentialstorage.dump
                    }
                }
            },
            'cookies': {
                'meta': 'Work with shared cookies',
                'commands': {
                    'get': {
                        'meta': 'Get the current apps shared cookies',
                        'flags': ['--json'],
                        'exec': cookies.get
                    }
                }
            },
            'ui': {
                'meta': 'iOS user interface commands',
                'commands': {
                    'alert': {
                        'meta': ('Show an alert message, optionally specifying the message to'
                                 'show. (Currently crashes iOS)'),
                        'exec': ui.alert
                    },
                    'dump': {
                        'meta': 'Dump the serialized UI',
                        'exec': ui.dump_ios_ui
                    },
                    'screenshot': {
                        'meta': 'Screenshot the current UIView',
                        'exec': ui.ios_screenshot
                    },
                    'biometrics_bypass': {
                        'meta': 'Hook the iOS Biometrics LAContext and respond with successful auth',
                        'exec': ui.bypass_touchid
                    }
                }
            },
            'heap': {
                'meta': 'Commands to work with the iOS heap',
                'commands': {
                    'print': {
                        'meta': 'Print information about objects on the iOS heap',
                        'commands': {
                            'ivars': {
                                'meta': 'Print instance variables for an Objective-C object',
                                'flags': ['--to-utf8'],
                                'exec': ios_heap.ivars
                            },
                            'methods': {
                                'meta': 'Print instance methods for an Objective-C object',
                                'flags': ['--without-arguments'],
                                'exec': ios_heap.methods
                            }
                        }
                    },
                    'search': {
                        'meta': 'Search for information about the current iOS heap',
                        'commands': {
                            'instances': {
                                'meta': 'Search for live instances of a particular class',
                                'exec': ios_heap.instances
                            }
                        }
                    },
                    'execute': {
                        'meta': 'Execute methods on objects on the iOS heap',
                        'flags': ['--return-string'],
                        'exec': ios_heap.execute
                    },
                    'evaluate': {
                        'meta': 'Evaluate JavaScript on objects on the iOS heap',
                        'flags': ['--inline'],
                        'exec': ios_heap.evaluate
                    }
                }
            },
            'hooking': {
                'meta': 'Commands used for hooking methods in iOS',
                'commands': {
                    'list': {
                        'meta': 'Lists various bits of information',
                        'commands': {
                            'classes': {
                                'meta': 'List classes available in the current application',
                                'exec': ios_hooking.show_ios_classes
                            },
                            'class_methods': {
                                'meta': 'List the methods in a class',
                                'flags': ['--include-parents'],
                                'exec': ios_hooking.show_ios_class_methods
                            }
                        }
                    },
                    'watch': {
                        'meta': 'Watch invocations of classes and methods',
                        'commands': {
                            'class': {
                                'meta': 'Hook all methods in a class and report on invocations',
                                'flags': ['--include-parents'],
                                'exec': ios_hooking.watch_class
                            },
                            'method': {
                                'meta': 'Hook a specific method and report on invocations',
                                'flags': ['--dump-args', '--dump-backtrace', '--dump-return'],
                                'exec': ios_hooking.watch_class_method
                            }
                        }
                    },
                    'set': {
                        'meta': 'Set various values',
                        'commands': {
                            'return_value': {
                                'meta': 'Set a methods return value. Supports only boolean returns',
                                'exec': ios_hooking.set_method_return_value
                            }
                        }
                    },
                    'search': {
                        'meta': 'Search for various classes and or methods',
                        'commands': {
                            'classes': {
                                'meta': 'Search for Objective-C classes matching a name',
                                'exec': ios_hooking.search_class
                            },
                            'methods': {
                                'meta': 'Search for Objective-C method matching a name',
                                'exec': ios_hooking.search_method
                            }
                        }
                    },
                    'generate': {
                        'meta': 'Generate Frida hooks for iOS',
                        'commands': {
                            'class': {
                                'meta': 'A generic hook manager for Classes',
                                'exec': ios_generate.clazz
                            },
                            'simple': {
                                'meta': 'Simple hooks for each Class method',
                                'exec': ios_generate.simple
                            }
                        }
                    }
                }
            },
            'pasteboard': {
                'meta': 'Work with the iOS pasteboard',
                'commands': {
                    'monitor': {
                        'meta': 'Monitor the iOS pasteboard',
                        'exec': pasteboard.monitor
                    }
                }
            },
            'sslpinning': {
                'meta': 'Work with iOS SSL pinning',
                'commands': {
                    'disable': {
                        'meta': 'Attempt to disable SSL pinning in various iOS libraries/classes',
                        'flags': ['--quiet'],
                        'exec': ios_pinning.ios_disable
                    }
                }
            },
            'jailbreak': {
                'meta': 'Work with iOS Jailbreak detection',
                'commands': {
                    'disable': {
                        'meta': 'Attempt to disable Jailbreak detection',
                        'exec': jailbreak.disable
                    },
                    'simulate': {
                        'meta': 'Attempt to simulate a Jailbroken environment',
                        'exec': jailbreak.simulate
                    },
                }
            },
            'monitor': {
                'meta': 'Commands to work with ios function monitoring',
                'commands': {
                    'crypto': {
                        'meta': 'Monitor CommonCrypto operations',
                        'exec': ios_crypto.crypto_enable
                    }
                },
            },
        }
    },

    'exit': {
        'meta': 'Exit',
    },
}
