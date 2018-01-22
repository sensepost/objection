import frida

class StateConnection(object):
    """ A class controlling the connection state of a device. """

    TYPE_USB = 0
    TYPE_REMOTE = 1

    def __init__(self) -> None:
        """
            Init a new connection state, defaulting to a USB
            connection.
        """

        self.usb = True
        self.network = False
        self.host = '127.0.0.1'
        self.port = 27042
        self._type = self.TYPE_USB
   
        self.gadget_name = 'Gadget'
        self.spawning = False

    def use_usb(self) -> None:
        """
            Sets the values required to have a USB connection.

            :return:
        """

        self.network = False
        self.usb = True
        self._type = self.TYPE_USB

    def use_network(self) -> None:
        """
            Sets the values required to have a Network connection.

            :return:
        """

        self.network = True
        self.usb = False
        self._type = self.TYPE_REMOTE

    def get_comms_type(self) -> int:
        """
            Returns the currently configured connection type.

            :return:
        """

        return self._type

    def get_comms_type_string(self) -> str:
        """
            Returns the currently configured connection type as a string.

            :return:
        """

        t = self.get_comms_type()

        if t == self.TYPE_USB:
            return 'usb'
        if t == self.TYPE_REMOTE:
            return 'net'

        return ''

    def __repr__(self) -> str:
        return '<State Usb:{0}, Network:{1}, Host:{2}, Port:{3}'.format(self.usb, self.network, self.host, self.port)


    def get_device(self):
        """
            Attempt to get a handle to the device.
        """
       
        if self.get_comms_type() == self.TYPE_USB:
            return frida.get_usb_device(5)

        if self.get_comms_type() == self.TYPE_REMOTE:
            try:
                return frida.get_device("tcp@%s:%d" % (self.host, self.port))
            except frida.TimedOutError:
                return frida.get_device_manager().add_remote_device(
                    "%s:%d" % (self.host, self.port))

    def spawn(self):
        '''
            Spawn the application with specified package name or bundle identifier.
        '''
        pid = self.get_device().spawn((self.gadget_name,)) 
        process_name = next((process.name for process in self.get_device().enumerate_processes() if process.pid == pid), None)

        # Update the package identifier to match the process name
        self.gadget_name = process_name
        self.spawning = True

    def resume(self):
        '''
            Resume recently spawned process.
        '''
        if not self.spawning:
            return 

        pid = None 
        try:           
            self.get_device().resume(self.get_pid())                               
        except:
            raise Exception("Failed to resume. Process not found.")

    def get_pid(self):
        '''
            Return the PID of the Gadget.
        '''
        return self.get_device().get_process(self.gadget_name).pid 

state_connection = StateConnection()
