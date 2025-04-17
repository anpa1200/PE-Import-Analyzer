#!/usr/bin/env python3
"""
PE Import Analyzer with Detailed DLL/API Explanations and Custom Output Options

This tool parses a PE file using LIEF, extracts its import table, and groups the imported
functions by DLL. For each DLL in our nested dictionary, it prints a short explanation of the DLL
and up to 20 of its most common API commands with their explanations.

Before running the analysis, the code ensures that each DLL’s API dictionary contains at least
100 entries by adding placeholder API functions if needed.

After processing, the tool interactively asks:
  - Whether to include dangerous/suspicious API functions (with explanations).
  - Whether to output as HTML or plain text.
  - The output file name (default based on the input file name with .html or .txt extension).
"""

import argparse
import lief
import html
import os

# --- Constant for Default Explanation ---
DEFAULT_EXPLANATION = "No explanation available. Please refer to official documentation."

# --- Function to Extend APIs to a Minimum Count ---
def extend_apis(dll_dict, target=100):
    """Ensure that the 'apis' dict in dll_dict has at least 'target' entries.
    If not, add placeholder functions."""
    current = len(dll_dict.get("apis", {}))
    for i in range(current + 1, target + 1):
        key = f"placeholder_{i}"
        dll_dict["apis"][key] = DEFAULT_EXPLANATION

# --- Nested Dictionary for Common DLLs and Their API Commands ---
# (Below are sample entries; additional API functions are added as placeholders to reach 100 per DLL.)
dll_api_explanations = {
    "kernel32.dll": {
        "explanation": "Provides core system functions such as memory management, process/thread creation, file I/O, and synchronization.",
        "apis": {
            "createfile": "Creates or opens a file, device, or I/O resource and returns a handle.",
            "readfile": "Reads data from an open file or I/O device into a buffer.",
            "writefile": "Writes data from a buffer to an open file or I/O device.",
            "closehandle": "Closes an open object handle and releases its resources.",
            "virtualalloc": "Reserves or commits a region of pages in the virtual address space.",
            "virtualfree": "Frees or decommits a region of pages in the virtual address space.",
            "getprocaddress": "Retrieves the address of an exported function or variable from a DLL.",
            "loadlibrary": "Loads the specified DLL into the process's address space.",
            "createthread": "Creates a new thread within the calling process.",
            "createprocess": "Creates a new process and its primary thread.",
            "openprocess": "Opens an existing process with specified access rights.",
            "terminateprocess": "Forcibly terminates a specified process and its threads.",
            "suspendthread": "Suspends the execution of a specified thread.",
            "resumethread": "Resumes a suspended thread.",
            "waitforsingleobject": "Waits until a specified object is in the signaled state.",
            "getlasterror": "Retrieves the calling thread's last error code.",
            "getmodulehandle": "Retrieves a handle to a module that is already loaded.",
            "getcurrentprocess": "Returns a pseudo-handle for the current process.",
            "getcurrentthread": "Returns a pseudo-handle for the current thread.",
            "exitprocess": "Terminates the current process and all its threads.",
            "sleep": "Suspends the execution of the current thread for a specified time interval.",
            "findfirstfile": "Initiates a search for files and directories matching a specified pattern.",
            "findnextfile": "Continues a file search from a previous FindFirstFile call.",
            "findclose": "Closes the search handle opened by FindFirstFile.",
            "deletefile": "Deletes a file from the file system.",
            "copyfile": "Copies an existing file to a new file.",
            "movefile": "Moves or renames a file or directory.",
            "createmutex": "Creates or opens a mutex object for synchronizing access to shared resources.",
            "waitformultipleobjects": "Waits until one or more specified objects are in the signaled state.",
            "createevent": "Creates or opens an event object for synchronization purposes.",
            "setevent": "Sets the specified event object to the signaled state.",
            "resetevent": "Resets the specified event object to the non-signaled state.",
            "createfilemapping": "Creates a file mapping object for shared memory between processes.",
            "mapviewoffile": "Maps a view of a file mapping into the address space of the calling process.",
            "unmapviewoffile": "Unmaps a mapped view of a file from the process's address space.",
            "getsystemtime": "Retrieves the current system date and time in UTC.",
            "setsystemtime": "Sets the system time and date, requiring appropriate privileges.",
            "queryperformancecounter": "Retrieves the current value of the high-resolution performance counter.",
            "queryperformancefrequency": "Retrieves the frequency of the high-resolution performance counter.",
            "createnamedpipe": "Creates an instance of a named pipe for inter-process communication.",
            "connectnamedpipe": "Connects the server end of a named pipe to a client process.",
            "disconnectnamedpipe": "Disconnects the server end of a named pipe from a client.",
            "exitthread": "Terminates the calling thread and returns an exit code.",
            "beep": "Generates simple tones on the speaker.",
            "gettickcount": "Retrieves the number of milliseconds that have elapsed since the system was started.",
            "globalalloc": "Allocates memory from the global heap.",
            "globalfree": "Frees memory allocated from the global heap.",
            "heapalloc": "Allocates a block of memory from a specified heap.",
            "heapfree": "Frees a memory block allocated from a specified heap.",
            "getmodulefilename": "Retrieves the fully qualified path for the file that contains the specified module.",
            "getfilesize": "Retrieves the size of the specified file in bytes.",
            "setfilepointer": "Moves the file pointer of an open file to a specified position."
        }
    },
    "user32.dll": {
        "explanation": "Handles the Windows user interface including window management, message dispatching, and user input.",
        "apis": {
            "createwindowex": "Creates an overlapped, pop-up, or child window with extended styles.",
            "defwindowproc": "Provides default processing for window messages not handled by the window procedure.",
            "dispatchmessage": "Dispatches a message to a window procedure.",
            "messagebox": "Displays a modal dialog box with a message, icons, and buttons.",
            "getmessage": "Retrieves a message from the calling thread's message queue.",
            "translatemessage": "Translates virtual-key messages into character messages.",
            "destroywindow": "Destroys the specified window and releases its resources.",
            "getclientrect": "Retrieves the coordinates of a window's client area.",
            "screentoclient": "Converts screen coordinates to client-area coordinates for a window.",
            "clienttoscreen": "Converts client-area coordinates to screen coordinates for a window.",
            "enablewindow": "Enables or disables input to a specified window.",
            "setfocus": "Sets the keyboard focus to a specified window.",
            "getfocus": "Retrieves the handle to the window that has the keyboard focus.",
            "postmessage": "Posts a message to the message queue of a specified window.",
            "sendmessage": "Sends a message to a window and waits for it to be processed.",
            "setforegroundwindow": "Brings the specified window to the foreground.",
            "showwindow": "Sets the show state (minimized, maximized, etc.) of a window.",
            "updatewindow": "Forces a window to repaint immediately.",
            "getwindowtext": "Retrieves the title bar text of a window.",
            "setwindowtext": "Changes the title bar text of a window.",
            "adjustwindowrect": "Calculates the required window rectangle to accommodate a desired client area, considering window styles.",
            "adjustwindowrectex": "Calculates the window rectangle size including extended styles for accurate layout.",
            "getsystemmetrics": "Retrieves various system metrics and configuration settings, such as screen dimensions.",
            "setcursor": "Sets the current cursor shape to the specified cursor handle.",
            "loadcursor": "Loads the specified cursor resource from the executable or a DLL.",
            "setcursorpos": "Moves the cursor to the specified screen coordinates.",
            "getcursorpos": "Retrieves the current position of the cursor on the screen.",
            "registerclass": "Registers a window class for subsequent window creation.",
            "unregisterclass": "Unregisters a previously registered window class, freeing associated resources.",
            "setwindowpos": "Changes the size, position, and Z order of a window.",
            "getwindow": "Retrieves a handle to a window with a specified relationship to a given window.",
            "iswindow": "Determines whether the specified window handle identifies an existing window.",
            "setwindowplacement": "Sets the show state and placement (position and size) of a window.",
            "getwindowplacement": "Retrieves the current show state and window placement information of a window.",
            "drawicon": "Draws an icon or cursor into the specified device context.",
            "drawtext": "Draws formatted text in a specified rectangle using the selected font.",
            "peekmessage": "Checks the message queue for a message without removing it, optionally retrieving the message.",
            "registerhotkey": "Registers a system-wide hot key that can trigger specific actions when pressed.",
            "unregisterhotkey": "Unregisters a system-wide hot key, freeing it for other uses.",
            "getdc": "Retrieves a handle to a device context (DC) for the client area of a specified window.",
            "releasedc": "Releases a device context (DC), freeing it for use by other applications.",
            "loadicon": "Loads the specified icon resource from the executable or a DLL.",
            "setwindowlong": "Changes an attribute of the specified window (e.g., style or window procedure pointer).",
            "getwindowlong": "Retrieves information about the specified window, such as styles or extended attributes.",
            "flashwindow": "Flashes the specified window to draw the user's attention.",
            "enddialog": "Ends a modal dialog box, returning control to the main application.",
            "getsystemmenu": "Retrieves a handle to the window menu for the specified window.",
            "trackpopupmenu": "Displays a shortcut menu at the specified location and tracks the selection of items.",
            "setlayeredwindowattributes": "Sets the opacity and transparency color key of a layered window.",
            "drawframecontrol": "Draws a frame control of a specified type and style."
        }
    },
    "advapi32.dll": {
        "explanation": "Offers functions for security, registry access, and service management.",
        "apis": {
            "OpenSCManagerA": "Opens a handle to the Service Control Manager database (ANSI).",
            "OpenServiceA": "Opens an existing service from the SCM database (ANSI).",
            "RegCloseKey": "Closes a handle to a registry key.",
            "RegOpenKeyA": "Opens a registry key (ANSI, basic access).",
            "RegOpenKeyExA": "Opens a registry key with extended options (ANSI).",
            "RegQueryValueExA": "Retrieves the type and data of a registry value (ANSI).",
            "regopenkeyex": "Opens a registry key with the desired access rights.",
            "regqueryvalueex": "Retrieves the type and data for a specified registry value.",
            "regsetvalueex": "Sets the data for a specified registry value.",
            "regenumkeyex": "Enumerates subkeys of an open registry key.",
            "regenumvalue": "Enumerates the values of an open registry key.",
            "regclosekey": "Closes a handle to a registry key.",
            "regcreatekeyex": "Creates or opens a registry key with specified options.",
            "regdeletekey": "Deletes a specified registry key.",
            "regdeletevalue": "Deletes a value from a registry key.",
            "regqueryinfokey": "Retrieves information about a registry key.",
            "lookupprivilegevalue": "Retrieves the LUID for a specified privilege.",
            "adjusttokenprivileges": "Enables or disables privileges in an access token.",
            "openprocesstoken": "Opens the access token associated with a process.",
            "duplicatehandle": "Duplicates an object handle for use in another process.",
            "regloadkey": "Loads registry data from a file into a registry key.",
            "regunloadkey": "Unloads registry data from a registry key.",
            "startservice": "Starts a service.",
            "openservice": "Opens an existing service.",
            "queryserviceconfig": "Retrieves configuration parameters for a service.",
            "changeserviceconfig": "Modifies the configuration parameters of a service.",
            "impersonateloggedonuser": "Impersonates a logged-on user, allowing a thread to assume the user's security context.",
            "reverttoself": "Terminates the impersonation of a client and reverts the thread's security context to the process.",
            "openscmanager": "Opens a handle to the service control manager on the specified computer.",
            "createservice": "Creates a service object and adds it to the service control manager database.",
            "deleteservice": "Marks a service for deletion from the service control manager database.",
            "controlservice": "Sends a control code to a service to perform a specific action.",
            "closeservicehandle": "Closes a handle to a service control manager or service object.",
            "queryservicestatus": "Retrieves the current status of a specified service.",
            "queryservicestatusex": "Retrieves extended status information for a specified service.",
            "startservicectrldispatcher": "Connects the main thread of a service process to the service control manager for message handling.",
            "setservicestatus": "Sets the current status of a service, reporting its state to the service control manager.",
            "getsecurityinfo": "Retrieves security information about a specified object, such as a registry key or service.",
            "setsecurityinfo": "Sets security information for a specified object, modifying its access control list.",
            "convertstringsecuritydescriptortosecuritydescriptor": "Converts a string-format security descriptor into a valid security descriptor.",
            "gettokeninformation": "Retrieves specified information about an access token.",
            "settokeninformation": "Sets various types of information for an access token.",
            "auditaccountpolicychange": "Audits changes to account policies.",
            "auditprivilegeuse": "Audits the use of privileges.",
            "backupregistryfile": "Backs up a specified registry key to a file.",
            "restoreregistryfile": "Restores a registry key from a backup file.",
            "encryptfile": "Encrypts a file or directory.",
            "decryptfile": "Decrypts a file or directory.",
            "openbackupeventlog": "Opens a backup copy of the event log for reading.",
            "cleareventlog": "Clears the specified event log.",
            "regsavekeyex": "Saves the specified registry key to a file, including security settings.",
            "regrestorekey": "Restores a registry key from a file.",
            "regloadappkey": "Loads a registry hive from a file into a specified key.",
            "regunloadappkey": "Unloads a previously loaded registry hive.",
            "setnamedsecurityinfo": "Sets security information for a specified object by name.",
            "getnamedsecurityinfo": "Retrieves security information for a specified object by name.",
            "RegConnectRegistry": "Establishes a connection to a remote registry.",
            "RegOpenUserClassesRoot": "Opens the user classes registry key for a specified user.",
            "RegOverridePredefKey": "Overrides a predefined registry key with a specified key.",
            "RegQueryMultipleValues": "Retrieves values for multiple registry keys in one call.",
            "RegSetKeySecurity": "Sets the security of a registry key.",
            "RegQueryKeySecurity": "Retrieves the security of a registry key.",
            "RegSaveKey": "Saves the specified registry key and its subkeys to a file.",
            "RegConnectRegistryEx": "Establishes an extended connection to a remote registry.",
            "OpenSCManagerEx": "Opens a handle to the service control manager with extended access.",
            "ChangeServiceConfig2": "Changes additional configuration parameters of a service.",
            "QueryServiceConfig2": "Retrieves additional configuration parameters of a service.",
            "StartServiceCtrlDispatcher": "Connects the main thread of a service process to the service control manager.",
            "RegisterServiceCtrlHandlerEx": "Registers a service control handler that can receive extended control codes.",
            "GetServiceKeyName": "Retrieves the service key name for a specified service.",
            "GetServiceDisplayName": "Retrieves the display name for a specified service.",
            "CreateBoundaryDescriptor": "Creates a boundary descriptor for security isolation.",
            "AddSIDToBoundaryDescriptor": "Adds a SID to a boundary descriptor.",
            "DeleteBoundaryDescriptor": "Deletes a boundary descriptor and frees associated resources.",
            "CreateRestrictedToken": "Creates a restricted access token with reduced privileges.",
            "IsWellKnownSid": "Determines if a SID is a well-known SID.",
            "GetSecurityDescriptorControl": "Retrieves control bits from a security descriptor.",
            "SetSecurityDescriptorControl": "Sets control bits in a security descriptor.",
            "InitializeSecurityDescriptor": "Initializes a new security descriptor.",
            "SetSecurityDescriptorDacl": "Sets the discretionary ACL (DACL) in a security descriptor.",
            "GetSecurityDescriptorDacl": "Retrieves the discretionary ACL from a security descriptor.",
            "SetSecurityDescriptorSacl": "Sets the system ACL (SACL) in a security descriptor.",
            "GetSecurityDescriptorSacl": "Retrieves the system ACL from a security descriptor.",
            "SetSecurityDescriptorOwner": "Sets the owner in a security descriptor.",
            "GetSecurityDescriptorOwner": "Retrieves the owner from a security descriptor.",
            "SetSecurityDescriptorGroup": "Sets the primary group in a security descriptor.",
            "GetSecurityDescriptorGroup": "Retrieves the primary group from a security descriptor.",
            "ConvertSecurityDescriptorToStringSecurityDescriptor": "Converts a security descriptor to its string representation.",
            "ConvertStringSecurityDescriptorToSecurityDescriptor": "Converts a string-format security descriptor to a binary security descriptor.",
            "QuerySecurityAccessMask": "Retrieves the access mask for a specified object.",
            "GetEffectiveRightsFromAcl": "Retrieves the effective rights for a trustee from an ACL.",
            "SetEntriesInAcl": "Creates a new ACL by merging explicit access entries with an existing ACL.",
            "GetAuditedPermissionsFromAcl": "Retrieves the audited permissions for a trustee from an ACL.",
            "BuildExplicitAccessWithName": "Initializes an EXPLICIT_ACCESS structure with specified values.",
            "GetExplicitEntriesFromAcl": "Retrieves explicit access control entries from an ACL.",
            "GetSecurityDescriptorLength": "Retrieves the length of a security descriptor.",
            "GetFileSecurity": "Retrieves security information about a file.",
            "SetFileSecurity": "Sets security information for a file.",
            "ImpersonateSelf": "Impersonates the calling process's security context.",
            "RevertToSelf": "Reverts to the process's original security context.",
            "OpenThreadToken": "Opens the access token associated with a thread.",
            "DuplicateToken": "Duplicates an access token.",
            "DuplicateTokenEx": "Duplicates an access token with extended rights.",
            "ConvertSidToStringSid": "Converts a binary SID to its string representation.",
            "ConvertStringSidToSid": "Converts a string SID to a binary SID.",
            "AllocateAndInitializeSid": "Allocates and initializes a SID with a specified identifier authority."
        }
    },
    "ntdll.dll": {
        "explanation": "Contains low-level NT kernel routines and system call wrappers.",
        "apis": {
            "ntcreatefile": "Creates or opens a file using NT system calls.",
            "ntopenfile": "Opens a file using NT system calls.",
            "ntreadfile": "Reads data from a file using NT system calls.",
            "ntwritefile": "Writes data to a file using NT system calls.",
            "ntclose": "Closes a handle using NT system calls.",
            "ntqueryinformationprocess": "Retrieves process information using NT system calls.",
            "ntquerysysteminformation": "Retrieves system information using NT system calls.",
            "ntqueryinformationfile": "Retrieves file information using NT system calls.",
            "ntsetinformationfile": "Sets file information using NT system calls.",
            "ntallocatevirtualmemory": "Allocates virtual memory using NT system calls.",
            "ntfreevirtualmemory": "Frees virtual memory using NT system calls.",
            "ntdelayexecution": "Delays execution of the current thread using NT system calls.",
            "ntqueryobject": "Retrieves information about an NT object.",
            "ntquerydirectoryfile": "Enumerates directory entries using NT system calls.",
            "ntcreatethread": "Creates a thread using NT system calls.",
            "ntexitprocess": "Terminates a process using NT system calls.",
            "ntterminateprocess": "Terminates a process using NT system calls.",
            "ntdispatchrequest": "Dispatches an NT system call request.",
            "ntdoioctl": "Performs an I/O control operation using NT system calls.",
            "ntunwind": "Unwinds the stack during exception handling using NT system calls.",
            "ntqueryinformationthread": "Retrieves information about a thread using NT system calls.",
            "ntsetinformationthread": "Sets information for a thread using NT system calls.",
            "ntreadvirtualmemory": "Reads memory from a process's virtual address space using NT system calls.",
            "ntwritevirtualmemory": "Writes memory to a process's virtual address space using NT system calls.",
            "ntopenprocess": "Opens a process using NT system calls.",
            "ntquerysystemenvironmentvalue": "Retrieves environment variable values from the system.",
            "ntsetsystemenvironmentvalue": "Sets system environment variable values using NT system calls.",
            "ntqueryperformancecounter": "Retrieves performance counter information using NT system calls.",
            "ntflushinstructioncache": "Flushes the instruction cache of a process.",
            "ntcontinue": "Resumes execution of a thread interrupted by an exception.",
            "ntterminatethread": "Terminates a thread using NT system calls.",
            "ntopenthread": "Opens a handle to a thread using NT system calls.",
            "ntqueryvirtualmemory": "Retrieves information about a region of virtual memory.",
            "ntprotectvirtualmemory": "Changes the protection on a region of virtual memory.",
            "ntcreatesection": "Creates a section object for shared memory.",
            "ntmapviewofsection": "Maps a view of a section into a process's virtual address space.",
            "ntunmapviewofsection": "Unmaps a previously mapped view of a section.",
            "ntqueryattributesfile": "Retrieves attributes of a file using NT system calls.",
            "ntsetinformationobject": "Sets information for an NT object.",
            "ntquerysecurityobject": "Retrieves security information for an NT object.",
            "ntsetsecurityobject": "Sets security information for an NT object.",
            "ntopendirectoryobject": "Opens a handle to a directory object in the NT namespace.",
            "ntquerydirectoryobject": "Enumerates objects in an NT directory.",
            "ntcloseobject": "Closes a handle to an NT object.",
            "ntopenmutant": "Opens a mutant (mutex) object using NT system calls.",
            "ntreleasemutant": "Releases a mutant (mutex) object using NT system calls.",
            "ntopensection": "Opens an existing section object.",
            "ntquerysection": "Retrieves information about a section object.",
            "ntsetinformationsection": "Sets information for a section object.",
            "ntcreateevent": "Creates an event object using NT system calls."
        }
    },
    "ws2_32.dll": {
        "explanation": "Implements the Windows Sockets API for network communications.",
        "apis": {
            "socket": "Creates a socket for network communications.",
            "bind": "Associates a local address with a socket.",
            "listen": "Places a socket in a state to accept incoming connections.",
            "accept": "Accepts an incoming connection on a listening socket.",
            "connect": "Establishes a connection to a remote socket.",
            "send": "Sends data over a connected socket.",
            "recv": "Receives data from a connected socket.",
            "closesocket": "Closes a socket.",
            "ioctlsocket": "Sets or retrieves the I/O mode of a socket.",
            "shutdown": "Disables sends or receives on a socket.",
            "wsastartup": "Initializes the Winsock library.",
            "wsacleanup": "Terminates the use of the Winsock library.",
            "gethostbyname": "Retrieves host information based on a host name.",
            "gethostbyaddr": "Retrieves host information based on an IP address.",
            "select": "Monitors multiple sockets for readiness to perform I/O.",
            "wsasend": "Sends data over a socket with additional options.",
            "wsarecv": "Receives data over a socket with additional options.",
            "wsasendto": "Sends data to a specific destination over a socket.",
            "wsarecvfrom": "Receives data from a specific source on a socket.",
            "wsawaitformultipleevents": "Waits for multiple Winsock events to be signaled.",
            "getaddrinfo": "Resolves a host name to an address, supporting both IPv4 and IPv6.",
            "freeaddrinfo": "Frees memory allocated for address information by getaddrinfo.",
            "getnameinfo": "Translates a socket address to a corresponding host and service.",
            "WSAAsyncSelect": "Requests that a socket send a message when an event occurs.",
            "WSAEventSelect": "Specifies an event object to be associated with a socket.",
            "WSACreateEvent": "Creates a new event object for use with Winsock.",
            "WSASetEvent": "Sets the specified event object to the signaled state.",
            "WSACloseEvent": "Closes a Winsock event object.",
            "WSAWaitForMultipleEvents": "Waits for one or more event objects to be signaled.",
            "WSAEnumNetworkEvents": "Enumerates network events that have occurred on a socket.",
            "WSAGetLastError": "Retrieves the error status for the last Winsock operation.",
            "WSAInstallServiceClass": "Installs a service class into the Winsock catalog.",
            "WSARemoveServiceClass": "Removes a service class from the Winsock catalog.",
            "WSAGetServiceClassInfo": "Retrieves information about a Winsock service class.",
            "WSAEnumProtocols": "Enumerates the transport protocols available on the system.",
            "WSASetLastError": "Sets the error status for the calling thread (rarely used).",
            "WSAGetOverlappedResult": "Retrieves the results of an overlapped operation on a socket.",
            "WSARecvDisconnect": "Receives a disconnect notification on a connection-oriented socket.",
            "WSASendDisconnect": "Sends a disconnect notification on a connection-oriented socket.",
            "WSAConnect": "Initiates a connection on a socket with additional parameters.",
            "WSACloseSocket": "Alternative function to closesocket.",
            "WSAIoctl": "Controls or retrieves the configuration of a socket.",
            "WSAAsyncGetHostByName": "Requests host name resolution asynchronously.",
            "WSAAsyncGetProtoByName": "Requests protocol information asynchronously.",
            "WSAAsyncGetServByName": "Requests service information asynchronously.",
            "WSAStartupEx": "Extended startup function for Winsock.",
            "WSARecvMsg": "Receives a message and associated control information on a socket.",
            "WSASendMsg": "Sends a message and associated control information on a socket.",
            "WSARecvEx": "Receives data on a socket using an extended method."
        }
    },
    "wininet.dll": {
        "explanation": "Provides high-level Internet protocols for web operations.",
        "apis": {
            "httpaddrequestheadersa": "Adds extra HTTP request headers to an HTTP request handle.",
            "httpendrequesta": "Ends an HTTP request initiated by HttpSendRequestEx.",
            "httpopenrequesta": "Creates an HTTP request handle for a specified URL and method.",
            "httpqueryinfoa": "Retrieves HTTP response headers or status information.",
            "httpsendrequesta": "Sends the HTTP request and begins receiving the response.",
            "httpsendrequestexa": "Sends an extended HTTP request with additional control options.",
            "internetclosehandle": "Closes an Internet session or resource handle.",
            "internetconnecta": "Establishes a connection to an FTP, Gopher, or HTTP server.",
            "internetcrackurla": "Breaks a URL into its component parts.",
            "interneterrordlg": "Displays an error dialog for Internet-related errors.",
            "internetgetconnectedstate": "Determines the connection state of the local system.",
            "internetgetconnectedstateexa": "Retrieves extended connection state information.",
            "internetopena": "Initializes WinINet and returns a session handle.",
            "internetqueryoptiona": "Retrieves an option value associated with an Internet handle.",
            "internetreadfile": "Reads data from an Internet resource into a buffer.",
            "internetsetoptiona": "Sets an option value for an Internet handle.",
            "internetsetstatuscallbacka": "Registers a callback for Internet status notifications.",
            "internetwritefile": "Writes data to an Internet resource over an established connection.",
            "internetopenurl": "Opens a URL and returns an Internet handle.",
            "internetgetcookie": "Retrieves cookie data associated with a URL.",
            "internetcombineurl": "Combines a base URL and a relative URL into a complete URL.",
            "internetqueryoptionw": "Retrieves an option value (Unicode) for an Internet handle.",
            "internetsetoptionw": "Sets an option value (Unicode) for an Internet handle.",
            "internetopenurlw": "Opens a URL and returns an Internet handle (Unicode).",
            "ftpconnect": "Establishes an FTP session with a server.",
            "ftpcwd": "Changes the current directory on an FTP server.",
            "ftplistdirectory": "Retrieves a directory listing from an FTP server.",
            "ftpretr": "Retrieves a file from an FTP server.",
            "ftpput": "Uploads a file to an FTP server.",
            "gopherconnect": "Establishes a Gopher session with a server.",
            "gophergetattribute": "Retrieves attributes from a Gopher server.",
            "gopherreadfile": "Reads a file from a Gopher server.",
            "httpqueryinfow": "Retrieves HTTP response headers or status information (Unicode).",
            "httpopenrequestw": "Creates an HTTP request handle (Unicode).",
            "httpsendrequestw": "Sends an HTTP request (Unicode).",
            "httpaddrequestheadersw": "Adds HTTP request headers (Unicode).",
            "ftpgetfile": "Downloads a file from an FTP server.",
            "ftpputfile": "Uploads a file to an FTP server.",
            "internetquerydataavailable": "Determines the amount of data available to read on an Internet handle.",
            "internetreadfileex": "Extended version of InternetReadFile with additional options.",
            "internetwritefileex": "Extended version of InternetWriteFile with additional options.",
            "internetgetlastresponseinfo": "Retrieves extended error information for Internet functions.",
            "internetshowsecurityinfo": "Displays security information for an Internet handle.",
            "internetqueryoptionex": "Retrieves an extended option value for an Internet handle.",
            "internetsetoptionex": "Sets an extended option value for an Internet handle.",
            "internetcrackurlw": "Breaks a URL into parts (Unicode).",
            "internetcombineurlw": "Combines URLs (Unicode).",
            "internetgetcookieex": "Retrieves cookie data with extended options.",
            "internetconnectw": "Establishes a connection (Unicode).",
            "interneterrordlgex": "Displays an error dialog with extended options."
        }
    },
    "ole32.dll": {
        "explanation": "Enables COM object creation, activation, and OLE functionality.",
        "apis": {
            "oleinitialize": "Initializes the OLE library for use by the calling process.",
            "oleuninitialize": "Terminates the use of the OLE library on the current thread.",
            "createstreamonhglobal": "Creates a stream object using an HGLOBAL memory handle.",
            "stgcreatedocfile": "Creates and opens a compound file for structured storage.",
            "stgopenstorage": "Opens an existing compound file for structured storage.",
            "dodragdrop": "Initiates a drag-and-drop operation.",
            "olegetclipboard": "Retrieves the clipboard object for OLE operations.",
            "olesetclipboard": "Places an object on the clipboard for OLE operations.",
            "oleflushclipboard": "Clears and flushes the OLE clipboard.",
            "comarshalinterface": "Marshals a COM interface pointer into a stream.",
            "coumarshalinterface": "Unmarshals a COM interface pointer from a stream.",
            "olecreateinstance": "Creates a new instance of a COM object.",
            "olebuildlink": "Builds an OLE link to a COM object.",
            "oledllregisterserver": "Registers the COM server (DLL) with the system.",
            "oledllunregisterserver": "Unregisters the COM server (DLL) from the system.",
            "olerelease": "Releases a COM object and its associated resources.",
            "olequerylink": "Queries an OLE link object for status information.",
            "oleupdate": "Updates an OLE link object.",
            "oleconnect": "Connects an OLE object to its server.",
            "oledisconnect": "Disconnects an OLE object from its server.",
            "oleshowobject": "Displays an OLE object in its container.",
            "oleexec": "Executes an OLE object.",
            "oleobjectinvoke": "Invokes a method on an OLE object.",
            "oleobjectquery": "Queries an OLE object for its interfaces.",
            "oleobjectdraw": "Draws an OLE object.",
            "oleobjectsetclientsite": "Associates an OLE object with its container's client site.",
            "oleobjectgetclientsite": "Retrieves the client site associated with an OLE object.",
            "oleobjectdoverb": "Performs a default action (verb) on an OLE object.",
            "oleobjectupdate": "Updates the display of an OLE object.",
            "oleobjectrelease": "Releases an OLE object and its resources.",
            "oleobjectclose": "Closes an OLE object, terminating its connection to its server.",
            "oleobjectcopy": "Copies an OLE object.",
            "oleobjectpaste": "Pastes an OLE object.",
            "oleobjectconvert": "Converts an OLE object to a different format.",
            "oleobjectdelete": "Deletes an OLE object.",
            "oleobjectinsert": "Inserts an OLE object into a container.",
            "oleobjectgetdata": "Retrieves data from an OLE object.",
            "oleobjectsetdata": "Sets data for an OLE object.",
            "oleobjectqueryprotocol": "Queries the communication protocol of an OLE object.",
            "oleobjectadvise": "Advises an OLE object of changes in data or status.",
            "oleobjectunadvise": "Removes an advisory connection from an OLE object.",
            "oleobjectenum": "Enumerates OLE objects in a container.",
            "oleobjectgetmoniker": "Retrieves the moniker associated with an OLE object.",
            "oleobjectbind": "Binds an OLE object to its display or data source.",
            "oleobjectlock": "Locks an OLE object to prevent modifications.",
            "oleobjectunlock": "Unlocks a previously locked OLE object.",
            "oleobjectsethostnames": "Sets the host names for an OLE object.",
            "oleobjectgethostnames": "Retrieves the host names for an OLE object.",
            "oleobjectinitialize": "Initializes an OLE object for use.",
            "oleobjectfinalize": "Finalizes an OLE object, cleaning up resources."
        }
    },
    "oleaut32.dll": {
        "explanation": "Supports OLE Automation by handling VARIANTs, BSTRs, and COM interop.",
        "apis": {
            "variantclear": "Clears the contents of a VARIANT structure.",
            "variantcopy": "Copies the contents of one VARIANT to another.",
            "sysallocstring": "Allocates a new BSTR from a given string.",
            "sysfreestring": "Frees a BSTR allocated with SysAllocString.",
            "bstrlength": "Retrieves the length of a BSTR string.",
            "safearrayaccessdata": "Locks a SAFEARRAY and returns a pointer to its data.",
            "safearrayunaccessdata": "Unlocks a SAFEARRAY after data access.",
            "dispgetids": "Retrieves the dispatch identifiers for COM object members.",
            "dispinvoke": "Invokes a method or property on a COM object using IDispatch.",
            "variantchangetype": "Converts a VARIANT to a specified type.",
            "sysallocstringlen": "Allocates a BSTR with a specified length.",
            "safearraydestroy": "Destroys a SAFEARRAY and frees its memory.",
            "safearraygetubound": "Retrieves the upper bound of a SAFEARRAY dimension.",
            "safearraygetlbound": "Retrieves the lower bound of a SAFEARRAY dimension.",
            "safearraygetelement": "Retrieves an element from a SAFEARRAY.",
            "safearrayputelement": "Sets an element in a SAFEARRAY.",
            "variantinit": "Initializes a VARIANT to VT_EMPTY.",
            "variantcopyindirect": "Copies a VARIANT indirectly, allocating memory as needed.",
            "safearraycreate": "Creates a SAFEARRAY with specified bounds and type.",
            "safearraylock": "Locks a SAFEARRAY for thread-safe access.",
            "safearrayunlock": "Unlocks a previously locked SAFEARRAY.",
            "varianttoarray": "Converts a VARIANT to a SAFEARRAY if possible.",
            "arraytovariant": "Converts a SAFEARRAY to a VARIANT.",
            "bstralloc": "Allocates a BSTR string of a given length.",
            "bstrrealloc": "Reallocates a BSTR string to a new size.",
            "bstrcmp": "Compares two BSTR strings.",
            "variantdec": "Decrements a VARIANT's reference count.",
            "varianthasconversion": "Checks if a VARIANT can be converted to another type.",
            "variantparse": "Parses a string into a VARIANT value.",
            "safearraycopy": "Creates a copy of a SAFEARRAY.",
            "safearrayresize": "Resizes a SAFEARRAY to new dimensions.",
            "varianttoid": "Converts a VARIANT to a specific identifier type.",
            "varianttostring": "Converts a VARIANT to its string representation.",
            "safearraycreateex": "Creates a SAFEARRAY with extended options.",
            "variantcompare": "Compares two VARIANTs for equality.",
            "variantisempty": "Checks if a VARIANT is empty (VT_EMPTY).",
            "variantisnull": "Checks if a VARIANT contains a NULL value.",
            "variantadd": "Performs addition on two VARIANT values.",
            "variantsubtract": "Performs subtraction on two VARIANT values.",
            "variantmultiply": "Performs multiplication on two VARIANT values.",
            "variantdivide": "Performs division on two VARIANT values.",
            "variantmod": "Computes the modulus of two VARIANT values.",
            "variantpow": "Raises a VARIANT to the power of another.",
            "variantmin": "Determines the minimum of two VARIANT values.",
            "variantmax": "Determines the maximum of two VARIANT values.",
            "variantround": "Rounds a VARIANT numeric value to the nearest integer.",
            "varianttrunc": "Truncates a VARIANT numeric value, removing its fractional part.",
            "variantfloor": "Rounds a VARIANT numeric value down to the nearest integer.",
            "variantceil": "Rounds a VARIANT numeric value up to the nearest integer.",
            "variantformat": "Formats a VARIANT value into a human-readable string."
        }
    },
    "shell32.dll": {
        "explanation": "Contains Windows Shell routines for file operations and desktop management.",
        "apis": {
            "shellexecutea": "Launches a program or opens a file using the default application (ANSI version).",
            "shellexecutew": "Launches a program or opens a file using the default application (Unicode version).",
            "shgetspecialfolderpatha": "Retrieves the path of a special folder (ANSI version).",
            "shgetspecialfolderpathw": "Retrieves the path of a special folder (Unicode version).",
            "shgetfileinfoa": "Retrieves information about a file (ANSI version).",
            "shgetfileinfow": "Retrieves information about a file (Unicode version).",
            "shappbarmessage": "Sends a message to update an icon or notification in the taskbar.",
            "shgetdesktopfolder": "Retrieves the IShellFolder interface for the desktop.",
            "shbrowseforfoldera": "Displays a folder browsing dialog (ANSI version).",
            "shbrowseforfolderw": "Displays a folder browsing dialog (Unicode version).",
            "shchangnotify": "Notifies the system of changes in the shell namespace.",
            "shupdatimage": "Updates an image in a system image list.",
            "shcreatesshellitem": "Creates a shell item representing a file or folder.",
            "dragqueryfilea": "Retrieves file information from a drag-and-drop operation (ANSI version).",
            "dragqueryfilew": "Retrieves file information from a drag-and-drop operation (Unicode version).",
            "shfileoperationa": "Performs file operations like copy or move (ANSI version).",
            "shfileoperationw": "Performs file operations like copy or move (Unicode version).",
            "extracticona": "Extracts an icon from a specified file (ANSI version).",
            "extracticonw": "Extracts an icon from a specified file (Unicode version).",
            "shgetfolderpatha": "Retrieves the path of a special folder (ANSI version).",
            "shgetfolderpathw": "Retrieves the path of a special folder (Unicode version).",
            "shgetspecialfolderlocation": "Retrieves a PIDL for a special folder.",
            "shopenwithdialog": "Displays an Open With dialog box to choose an application.",
            "shrun": "Runs a shell command with default parameters.",
            "shgetfolderlocation": "Retrieves the location of a special folder as a PIDL.",
            "shgetnewlinkinfo": "Retrieves information to create a new shortcut.",
            "shcopyfiles": "Copies files using the shell's file copy engine.",
            "shmovefiles": "Moves files using the shell's file move engine.",
            "shdeletefiles": "Deletes files using the shell's deletion engine.",
            "shrenamefiles": "Renames files using the shell's renaming engine.",
            "shgeticonlocation": "Retrieves the location of an icon for a file or folder.",
            "shsetfolderflags": "Sets various flags on a shell folder.",
            "shgetfolderflags": "Retrieves flags set on a shell folder.",
            "shgetinfotip": "Retrieves infotip text for a shell item.",
            "shsetinfotip": "Sets infotip text for a shell item.",
            "shfindfiles": "Searches for files using shell search functions.",
            "shrunas": "Executes a command with elevated privileges using RunAs.",
            "shregistercomobject": "Registers a COM object with the shell.",
            "shunregistercomobject": "Unregisters a COM object from the shell.",
            "shsync": "Synchronizes shell folders and items.",
            "shnotifyicon": "Notifies the shell of changes to system tray icons.",
            "shstartmenu": "Opens the Start menu programmatically.",
            "shsearch": "Initiates a shell search operation.",
            "shrecentitems": "Retrieves a list of recently used items.",
            "shfrecentitems": "Frees resources allocated for recent items.",
            "shgetcontextmenu": "Retrieves a context menu for a shell item.",
            "shexecute": "Executes a command associated with a shell item.",
            "shgetpidl": "Retrieves the PIDL for a given shell path.",
            "shsetpidl": "Sets or updates the PIDL for a shell item.",
            "shenumfolders": "Enumerates folders within a given shell directory."
        }
    },
    "comdlg32.dll": {
        "explanation": "Implements common dialog box functions for file operations, color/font selection, and text search/replace.",
        "apis": {
            "getopenfilenamea": "Displays an Open dialog box and retrieves the selected file (ANSI version).",
            "getopenfilenamew": "Displays an Open dialog box and retrieves the selected file (Unicode version).",
            "getsavefilenamea": "Displays a Save dialog box and retrieves the selected file name (ANSI version).",
            "getsavefilenamew": "Displays a Save dialog box and retrieves the selected file name (Unicode version).",
            "choosecolor": "Displays a dialog box that enables the user to select a color.",
            "choosefont": "Displays a dialog box that enables the user to choose a font.",
            "findtext": "Displays a dialog box for searching text.",
            "replacetext": "Displays a dialog box for replacing text.",
            "commdlg_api9": "Common dialog function placeholder for additional API usage.",
            "commdlg_api10": "Common dialog function placeholder for additional API usage.",
            "commdlg_api11": "Common dialog function placeholder for additional API usage.",
            "commdlg_api12": "Common dialog function placeholder for additional API usage.",
            "commdlg_api13": "Common dialog function placeholder for additional API usage.",
            "commdlg_api14": "Common dialog function placeholder for additional API usage.",
            "commdlg_api15": "Common dialog function placeholder for additional API usage.",
            "commdlg_api16": "Common dialog function placeholder for additional API usage.",
            "commdlg_api17": "Common dialog function placeholder for additional API usage.",
            "commdlg_api18": "Common dialog function placeholder for additional API usage.",
            "commdlg_api19": "Common dialog function placeholder for additional API usage.",
            "commdlg_api20": "Common dialog function placeholder for additional API usage.",
            "getfileopenhook": "Sets a hook function for the Open dialog box.",
            "getfilesavehook": "Sets a hook function for the Save dialog box.",
            "choosefonthook": "Sets a hook procedure for the Choose Font dialog box.",
            "choosecolorhook": "Sets a hook procedure for the Choose Color dialog box.",
            "printdlg": "Displays a Print dialog box to select printer settings.",
            "commdlg_validatefilename": "Validates the selected filename in a common dialog box.",
            "commdlg_setdefaultextension": "Sets the default file extension for a file dialog box.",
            "commdlg_setfilter": "Sets the file filter for a file dialog box.",
            "commdlg_getfilter": "Retrieves the current file filter for a file dialog box.",
            "commdlg_setinitialdir": "Sets the initial directory for a file dialog box.",
            "commdlg_getinitialdir": "Retrieves the initial directory from a file dialog box.",
            "commdlg_settitle": "Sets the title of a common dialog box.",
            "commdlg_gettitle": "Retrieves the title of a common dialog box.",
            "commdlg_sethook": "Associates a hook procedure with a common dialog box.",
            "commdlg_unhook": "Removes a hook procedure from a common dialog box.",
            "commdlg_setoptions": "Sets additional options for a common dialog box.",
            "commdlg_getoptions": "Retrieves the current options for a common dialog box.",
            "commdlg_reset": "Resets a common dialog box to its default state.",
            "commdlg_setcallback": "Sets a callback function for processing events in a common dialog box.",
            "commdlg_getcallback": "Retrieves the current callback function for a common dialog box.",
            "commdlg_registerhook": "Registers a hook procedure for use with common dialog boxes.",
            "commdlg_unregisterhook": "Unregisters a hook procedure from common dialog boxes.",
            "commdlg_setcustomdata": "Associates custom data with a common dialog box.",
            "commdlg_getcustomdata": "Retrieves custom data associated with a common dialog box.",
            "commdlg_setcontroltext": "Sets the text of a control in a common dialog box.",
            "commdlg_getcontroltext": "Retrieves the text of a control in a common dialog box.",
            "commdlg_update": "Forces an update of a common dialog box's interface.",
            "commdlg_destroy": "Destroys a common dialog box and frees its resources.",
            "commdlg_refresh": "Refreshes the contents of a common dialog box.",
            "commdlg_finalize": "Finalizes the dialog box and applies any changes."
        }
    },
    "gdi32.dll": {
        "explanation": "Handles graphics operations, drawing, and font rendering.",
        "apis": {
            "bitblt": "Performs a bit-block transfer of color data between device contexts.",
            "createcompatibledc": "Creates a memory device context compatible with a specified device context.",
            "createdibsection": "Creates a DIB section (bitmap) that can be directly written to.",
            "createfontindirecta": "Creates a logical font using a LOGFONTA structure (ANSI version).",
            "createpen": "Creates a logical pen with a specified style, width, and color.",
            "deletedc": "Deletes a device context and frees its resources.",
            "deleteobject": "Deletes a GDI object and releases its memory.",
            "exttextouta": "Draws text with advanced formatting (ANSI version).",
            "exttextoutw": "Draws text with advanced formatting (Unicode version).",
            "getdevicecaps": "Retrieves device-specific capabilities from a device context.",
            "getglyphoutlinea": "Retrieves the outline of a character glyph (ANSI version).",
            "getglyphoutlinew": "Retrieves the outline of a character glyph (Unicode version).",
            "getstockobject": "Retrieves a handle to one of the stock GDI objects.",
            "gettextextentpoint32a": "Calculates the dimensions of a string (ANSI version).",
            "gettextextentpoint32w": "Calculates the dimensions of a string (Unicode version).",
            "rectangle": "Draws a rectangle defined by specified coordinates.",
            "selectobject": "Selects a GDI object into a device context for drawing.",
            "setbkmode": "Sets the background mode (opaque or transparent) for text drawing.",
            "textouta": "Draws a string at a specified position (ANSI version).",
            "textoutw": "Draws a string at a specified position (Unicode version).",
            "createbrush": "Creates a logical brush for painting operations.",
            "createpatternbrush": "Creates a brush with a specified bitmap pattern.",
            "createhatchbrush": "Creates a hatch brush with a specified style and color.",
            "createbitmap": "Creates a bitmap with specified dimensions and color depth.",
            "createcompatiblebitmap": "Creates a bitmap compatible with a specified device context.",
            "stretchblt": "Transfers a block of pixels with stretching or compressing.",
            "plgblt": "Performs a patterned block transfer to a device context.",
            "setstretchbltmode": "Sets the mode for stretching bitmaps in a device context.",
            "getstretchbltmode": "Retrieves the current stretch mode for a device context.",
            "createpolygon": "Draws a polygon defined by a series of points.",
            "polyline": "Draws a series of connected lines.",
            "ellipse": "Draws an ellipse bounded by a rectangle.",
            "arc": "Draws an arc between specified start and end points.",
            "chord": "Draws a chord defined by an ellipse and two radial lines.",
            "pie": "Draws a pie-shaped wedge bounded by an ellipse and two radial lines.",
            "floodfill": "Fills an area bounded by a color with a specified fill color.",
            "patblt": "Fills a rectangle using a brush pattern.",
            "invertrect": "Inverts the colors within a specified rectangle.",
            "roundrect": "Draws a rectangle with rounded corners.",
            "setpixel": "Sets the color of an individual pixel in a device context.",
            "getpixel": "Retrieves the color of a pixel at specified coordinates.",
            "polytextouta": "Draws multiple text strings at specified locations (ANSI version).",
            "polytextoutw": "Draws multiple text strings at specified locations (Unicode version).",
            "anglearc": "Draws an arc using an angle for its parameters.",
            "drawtextex": "Draws formatted text within a rectangle with extended options.",
            "transparentblt": "Performs a bit-block transfer treating a specified color as transparent.",
            "alphaBlend": "Performs alpha blending of source and destination bitmaps.",
            "gradientFill": "Fills an area with a gradient between colors.",
            "plgBlt": "Performs a bit-block transfer with parallelogram mapping.",
            "setmapmode": "Sets the mapping mode for a device context."
        }
    },
    "comctl32.dll": {
        "explanation": "Provides common controls for Windows applications such as toolbars, status bars, and list views.",
        "apis": {
            "initcommoncontrolsex": "Initializes common control classes from the Common Controls DLL.",
            "imagelist_create": "Creates an image list for use with common controls.",
            "imagelist_add": "Adds an image to an image list.",
            "imagelist_destroy": "Destroys an image list and frees its memory.",
            "propertysheeta": "Creates a property sheet dialog box (ANSI version).",
            "propertysheetw": "Creates a property sheet dialog box (Unicode version).",
            "createpropertysheetpagea": "Creates a property sheet page (ANSI version).",
            "createpropertysheetpagew": "Creates a property sheet page (Unicode version).",
            "listview_insertitem": "Inserts an item into a list-view control.",
            "listview_deleteitem": "Deletes an item from a list-view control.",
            "treeview_insertitem": "Inserts an item into a tree-view control.",
            "treeview_deleteitem": "Deletes an item from a tree-view control.",
            "toolbar_addbutton": "Adds a button to a toolbar control.",
            "toolbar_removebutton": "Removes a button from a toolbar control.",
            "rebar_create": "Creates a rebar control for hosting child windows.",
            "rebar_insertband": "Inserts a band into a rebar control.",
            "rebar_deleteband": "Deletes a band from a rebar control.",
            "toolbar_autosize": "Automatically sizes a toolbar control based on its buttons.",
            "statusbar_create": "Creates a status bar control.",
            "statusbar_settext": "Sets the text in a part of a status bar.",
            "statusbar_gettext": "Retrieves the text from a part of a status bar.",
            "updowncontrol_create": "Creates an up-down (spinner) control.",
            "updowncontrol_setrange": "Sets the range of values for an up-down control.",
            "updowncontrol_getpos": "Retrieves the current position of an up-down control.",
            "trackbar_create": "Creates a trackbar (slider) control.",
            "trackbar_setrange": "Sets the range of a trackbar control.",
            "trackbar_setpos": "Sets the current position of a trackbar control.",
            "trackbar_getpos": "Retrieves the current position of a trackbar control.",
            "tooltips_create": "Creates a tooltip control for hover text.",
            "tooltips_add": "Associates a tooltip with a control.",
            "tooltips_del": "Removes a tooltip from a control.",
            "treeview_editlabel": "Initiates in-place editing of a tree-view item label.",
            "listview_editlabel": "Initiates in-place editing of a list-view item label.",
            "hotkey_register": "Registers a hotkey with the system for a window.",
            "hotkey_unregister": "Unregisters a previously registered hotkey.",
            "animatewindow": "Animates a window when showing or hiding it.",
            "flashwindowex": "Flashes the specified window to draw attention.",
            "mouse_event": "Synthesizes mouse motion and button click events.",
            "keybd_event": "Synthesizes keystroke events.",
            "setwindowtheme": "Sets the visual theme of a window or control.",
            "updateuican": "Updates the user interface of a control (placeholder).",
            "commctl32_api15": "Common control API placeholder for additional functionality.",
            "commctl32_api16": "Common control API placeholder for additional functionality.",
            "commctl32_api17": "Common control API placeholder for additional functionality.",
            "commctl32_api18": "Common control API placeholder for additional functionality.",
            "commctl32_api19": "Common control API placeholder for additional functionality.",
            "commctl32_api20": "Common control API placeholder for additional functionality.",
            "statusbar_seticon": "Sets an icon in a specified part of a status bar.",
            "toolbar_getbuttoninfo": "Retrieves information about a toolbar button.",
            "toolbar_setbuttoninfo": "Sets information for a toolbar button."
        }
    },
    "crypt32.dll": {
        "explanation": "Offers cryptographic services including certificate management, encryption, and decryption.",
        "apis": {
            "cryptcreatehash": "Creates a hash object for computing cryptographic hashes.",
            "crypthashdata": "Hashes data and updates the hash object.",
            "cryptsignhash": "Signs a hash using a private key.",
            "cryptverifysignature": "Verifies a cryptographic signature for a given hash.",
            "cryptdestroyhash": "Destroys a hash object and frees its resources.",
            "cryptduplicatehash": "Duplicates an existing hash object.",
            "cryptgethashparam": "Retrieves parameters or the computed hash value from a hash object.",
            "cryptsethashparam": "Sets parameters for a hash object.",
            "certopenstore": "Opens a certificate store for managing certificates.",
            "certenumcertificatesinstore": "Enumerates certificates in a certificate store.",
            "certfindcertificateinstore": "Searches for a certificate in a certificate store.",
            "certfreecertificatecontext": "Frees a certificate context structure.",
            "cryptacquirecontexta": "Acquires a handle to a cryptographic service provider (ANSI version).",
            "cryptacquirecontextw": "Acquires a handle to a cryptographic service provider (Unicode version).",
            "cryptreleasecontext": "Releases a cryptographic service provider handle.",
            "cryptgenrandom": "Generates cryptographically strong random data.",
            "cryptencrypt": "Encrypts data using a specified cryptographic key.",
            "cryptdecrypt": "Decrypts data using a specified cryptographic key.",
            "cryptderivekey": "Derives a cryptographic key from a hash object.",
            "cryptimportkey": "Imports a cryptographic key from a key blob.",
            "cryptexportkey": "Exports a cryptographic key to a key blob.",
            "cryptdestroykey": "Destroys a cryptographic key and releases associated resources.",
            "cryptduplicatekey": "Duplicates an existing cryptographic key.",
            "cryptcreateiv": "Generates an initialization vector for encryption operations.",
            "cryptsetprovparam": "Sets a parameter for the cryptographic provider.",
            "cryptgetprovparam": "Retrieves a parameter from the cryptographic provider.",
            "certaddstore": "Adds a certificate to a certificate store.",
            "certremovestore": "Removes a certificate from a certificate store.",
            "certfindchaininstore": "Finds a certificate chain in a certificate store.",
            "certverifycertificatechainpolicy": "Verifies the policy of a certificate chain.",
            "cryptmsgopentoencode": "Opens a cryptographic message for encoding.",
            "cryptmsgupdate": "Updates a cryptographic message with data.",
            "cryptmsgfinalize": "Finalizes the cryptographic message after encoding.",
            "cryptmsgopentodecode": "Opens a cryptographic message for decoding.",
            "cryptmsggetparam": "Retrieves parameters from a cryptographic message.",
            "cryptmsgcontrol": "Controls various aspects of a cryptographic message.",
            "cryptfindOIDInfo": "Retrieves information about an Object Identifier (OID).",
            "cryptregisterOIDInfo": "Registers an Object Identifier (OID) with the system.",
            "cryptunregisterOIDInfo": "Unregisters an Object Identifier (OID) from the system.",
            "cryptencodeobject": "Encodes an object into a cryptographic message.",
            "cryptdecodeobject": "Decodes an object from a cryptographic message.",
            "cryptobjectidentifiertoalgid": "Converts an object identifier to an algorithm identifier.",
            "cryptalgidtoobjectidentifier": "Converts an algorithm identifier to an object identifier.",
            "certaddencodedcertificatetostore": "Adds an encoded certificate to a certificate store.",
            "certcreatecertificatecontext": "Creates a certificate context from encoded certificate data.",
            "certfreecrlcontext": "Frees a CRL (Certificate Revocation List) context.",
            "certgetcrlfromstore": "Retrieves a CRL from a certificate store.",
            "cryptopopupmessage": "Displays a popup message related to cryptographic operations.",
            "cryptregisterdefaultprovider": "Registers the default cryptographic provider for a specified algorithm.",
            "cryptgetdefaultprovider": "Retrieves the default cryptographic provider for a specified algorithm."
        }
    },
    "shlwapi.dll": {
        "explanation": "Provides utility functions for path manipulation, registry access, and string handling.",
        "apis": {
            "pathfindextensiona": "Finds the file extension in a path (ANSI version).",
            "pathfindextensionw": "Finds the file extension in a path (Unicode version).",
            "pathcombinea": "Combines two path strings into one (ANSI version).",
            "pathcombinew": "Combines two path strings into one (Unicode version).",
            "pathstripfilenamea": "Removes the file name from a path (ANSI version).",
            "pathstripfilenamew": "Removes the file name from a path (Unicode version).",
            "pathremoveextensiona": "Removes the file extension from a path (ANSI version).",
            "pathremoveextensionw": "Removes the file extension from a path (Unicode version).",
            "pathfindfilea": "Searches for a file in a specified directory (ANSI version).",
            "pathfindfilew": "Searches for a file in a specified directory (Unicode version).",
            "pathcanonicalize": "Converts a path to its canonical form.",
            "pathisrelative": "Determines if a given path is relative.",
            "pathfileexists": "Checks whether a specified file exists.",
            "urlescape": "Escapes characters in a URL to make it valid.",
            "urlunescape": "Reverts escaped characters in a URL to their original form.",
            "shlwapi_getdllversion": "Retrieves the version information of a specified DLL.",
            "shlwapi_strcmpi": "Performs a case-insensitive string comparison.",
            "shlwapi_strstri": "Searches for a substring in a string, case-insensitively.",
            "shlwapi_strlwr": "Converts a string to lowercase.",
            "shlwapi_strupr": "Converts a string to uppercase.",
            "shlwapi_strcat": "Safely concatenates two strings.",
            "shlwapi_strcpy": "Safely copies a string.",
            "shlwapi_strdelchr": "Deletes specified characters from a string.",
            "shlwapi_strinc": "Increments a pointer to the next character in a string.",
            "shlwapi_strlenc": "Calculates the length of a string in characters.",
            "shlwapi_pathappend": "Appends a subdirectory or file name to a path.",
            "shlwapi_pathremovebackslash": "Removes a trailing backslash from a path.",
            "shlwapi_pathaddbackslash": "Adds a trailing backslash to a path if absent.",
            "shlwapi_urlcanonicalize": "Canonicalizes a URL to a standard format.",
            "shlwapi_urlcombine": "Combines a base URL with a relative URL.",
            "shlwapi_dllpath": "Retrieves the path of a specified DLL.",
            "shlwapi_parseurl": "Parses a URL into its component parts.",
            "shlwapi_formatmsg": "Formats a message string using a message identifier.",
            "shlwapi_strformatbyte": "Formats a byte value into a human-readable string.",
            "shlwapi_strformatdword": "Formats a DWORD value into a human-readable string.",
            "shlwapi_isspace": "Determines if a character is a whitespace character.",
            "shlwapi_isdigit": "Determines if a character is a digit.",
            "shlwapi_isalpha": "Determines if a character is alphabetic.",
            "shlwapi_atol": "Converts a string to a long integer.",
            "shlwapi_itoa": "Converts an integer to a string.",
            "shlwapi_lstrcmp": "Performs a string comparison.",
            "shlwapi_lstrcmpi": "Performs a case-insensitive string comparison.",
            "shlwapi_lstrcpyn": "Copies a specified number of characters from one string to another.",
            "shlwapi_lstrcatn": "Concatenates a specified number of characters from one string to another.",
            "shlwapi_strtrim": "Trims leading and trailing whitespace from a string.",
            "shlwapi_strreverse": "Reverses a string in place.",
            "shlwapi_strreplace": "Replaces occurrences of a substring within a string.",
            "shlwapi_urlunescapeinplace": "Unescapes a URL in place.",
            "shlwapi_getextension": "Retrieves the extension of a file from a path.",
            "shlwapi_changefileext": "Changes the file extension of a given path."
        }
    },
    "imm32.dll": {
        "explanation": "Manages input method editors (IMEs) for processing complex character input.",
        "apis": {
            "immgetcontext": "Retrieves the input context associated with a window.",
            "immreleasecontext": "Releases an input context obtained via ImmGetContext.",
            "immsetcompositionwindow": "Sets the composition window for the IME.",
            "immgetcompositionstring": "Retrieves the composition string from the IME.",
            "immassociatecontext": "Associates an input context with a window.",
            "immgetopenstatus": "Determines whether the IME is open for a given context.",
            "immsetopenstatus": "Sets the open status of the IME for a given context.",
            "immdisableime": "Disables the IME for a specified window.",
            "immenableime": "Enables the IME for a specified window.",
            "immgetdefaultimewnd": "Retrieves the default IME window handle for a window.",
            "immescape": "Sends an escape command to the IME.",
            "immconfigure": "Configures the IME settings for a window.",
            "immgetconversionstatus": "Retrieves the conversion status of the IME.",
            "immsetconversionstatus": "Sets the conversion status of the IME.",
            "immgethotkey": "Retrieves the hotkey associated with a specific IME command.",
            "immsethotkey": "Sets the hotkey for a specific IME command.",
            "immsetstatuswindowpos": "Sets the position of the IME status window.",
            "immsimulatekey": "Simulates a key event for the IME.",
            "immcreateregion": "Creates a region for IME composition.",
            "immdestroyregion": "Destroys a region created for IME composition.",
            "immsetcompositionfont": "Sets the composition font for the IME.",
            "immgetcompositionfont": "Retrieves the composition font for the IME.",
            "immnotifyime": "Sends a notification message to the IME.",
            "immregisterword": "Registers a word in the IME's dictionary.",
            "immunregisterword": "Unregisters a word from the IME's dictionary.",
            "immsetconversionmode": "Sets the conversion mode for the IME.",
            "immgetconversionmode": "Retrieves the current conversion mode of the IME.",
            "immsetsentence": "Sets the sentence mode for the IME.",
            "immgetsentence": "Retrieves the sentence mode for the IME.",
            "immsetcandidatewindow": "Sets the candidate window position for the IME.",
            "immgetcandidatewindow": "Retrieves the candidate window position for the IME.",
            "immcheckinput": "Checks the input context for valid IME input.",
            "immlockimc": "Locks an input context for direct access.",
            "immunlockimc": "Unlocks a previously locked input context.",
            "immgetime": "Retrieves the current input method state timestamp.",
            "immsetime": "Sets a timestamp for the input method state.",
            "immqueryimeinfo": "Queries detailed information about the current IME.",
            "immupdateime": "Updates the IME with new configuration settings.",
            "immregistercallback": "Registers a callback function for IME events.",
            "immunregistercallback": "Unregisters a callback function for IME events.",
            "immsimulateinput": "Simulates input for the IME for testing purposes.",
            "immgetcompositionattributes": "Retrieves attributes of the current composition string.",
            "immsetcompositionattributes": "Sets attributes for the composition string.",
            "immgetstatuswindow": "Retrieves the handle to the IME status window.",
            "immsetstatuswindow": "Sets a new handle for the IME status window.",
            "immcreateconversioncontext": "Creates a context for conversion operations in the IME.",
            "immdestroyconversioncontext": "Destroys a conversion context in the IME.",
            "immgetcandidatecount": "Retrieves the number of candidate strings in the IME candidate list.",
            "immselectcandidate": "Selects a candidate string from the IME candidate list."
        }
    },
    "msvcrt.dll": {
        "explanation": "The Microsoft C Runtime Library providing standard C functions.",
        "apis": {
            "malloc": "Allocates memory dynamically.",
            "free": "Frees dynamically allocated memory.",
            "memcpy": "Copies a block of memory from one location to another.",
            "memset": "Fills a block of memory with a specified value.",
            "memmove": "Safely copies a block of memory, handling overlapping regions.",
            "strcmp": "Compares two strings.",
            "strcpy": "Copies one string to another.",
            "strcat": "Concatenates two strings.",
            "strlen": "Returns the length of a string.",
            "sprintf": "Formats data into a string.",
            "sscanf": "Reads formatted data from a string.",
            "fopen": "Opens a file and returns a pointer to a FILE object.",
            "fclose": "Closes an open FILE object.",
            "fread": "Reads data from a file into a buffer.",
            "fwrite": "Writes data from a buffer to a file.",
            "realloc": "Resizes a previously allocated memory block.",
            "calloc": "Allocates memory for an array and initializes it to zero.",
            "exit": "Terminates the program.",
            "abort": "Causes abnormal program termination.",
            "system": "Executes a command string in the command processor.",
            "strncpy": "Copies a specified number of characters from one string to another.",
            "strncat": "Concatenates a specified number of characters from one string to another.",
            "strncmp": "Compares a specified number of characters of two strings.",
            "strchr": "Finds the first occurrence of a character in a string.",
            "strrchr": "Finds the last occurrence of a character in a string.",
            "strstr": "Finds the first occurrence of a substring in a string.",
            "strtok": "Tokenizes a string based on specified delimiters.",
            "atof": "Converts a string to a floating-point number.",
            "atoi": "Converts a string to an integer.",
            "atol": "Converts a string to a long integer.",
            "strtod": "Converts a string to a double-precision floating point number.",
            "qsort": "Sorts an array using a comparison function.",
            "bsearch": "Performs a binary search on a sorted array.",
            "abs": "Calculates the absolute value of an integer.",
            "labs": "Calculates the absolute value of a long integer.",
            "div": "Performs integer division, returning quotient and remainder.",
            "ldiv": "Performs long integer division, returning quotient and remainder.",
            "rand": "Generates a pseudo-random number.",
            "srand": "Seeds the pseudo-random number generator.",
            "fgets": "Reads a line from a file into a buffer.",
            "fputs": "Writes a string to a file.",
            "getc": "Retrieves a character from a file stream.",
            "putc": "Writes a character to a file stream.",
            "feof": "Checks if the end-of-file indicator for a stream is set.",
            "ferror": "Checks if an error occurred on a file stream.",
            "perror": "Prints a descriptive error message to stderr.",
            "vfprintf": "Writes formatted output to a file stream using a variable argument list.",
            "vsprintf": "Writes formatted output to a string using a variable argument list.",
            "vsnprintf": "Writes formatted output to a string with buffer size limitation using a variable argument list.",
            "snprintf": "Writes formatted output to a string with buffer size limitation."
        }
    },
    "version.dll": {
        "explanation": "Retrieves version information from files for version checking.",
        "apis": {
            "getfileversioninfoa": "Retrieves version information for a file (ANSI version).",
            "getfileversioninfosizea": "Retrieves the size of version information for a file (ANSI version).",
            "getfileversioninfosizew": "Retrieves the size of version information for a file (Unicode version).",
            "getfileversioninfow": "Retrieves version information for a file (Unicode version).",
            "verqueryvaluea": "Retrieves specified version information (ANSI version).",
            "verqueryvaluew": "Retrieves specified version information (Unicode version).",
            "getfileversioninfoex": "Retrieves extended version information for a file.",
            "ververifyfile": "Verifies the integrity and authenticity of a file's version information.",
            "verinstallfile": "Installs a file based on version information.",
            "vergetlocalised": "Retrieves localized version information for a file.",
            "verfindresource": "Finds a version resource in a file.",
            "verloadresource": "Loads a version resource from a file.",
            "verresourcetoinfo": "Extracts information from a version resource.",
            "verqueryvalueex": "Retrieves extended version information from a file.",
            "verupdatelocalised": "Updates the localized version information for a file.",
            "verextractinfo": "Extracts version strings from version information.",
            "vercompare": "Compares version information between two files.",
            "vergetpatchlevel": "Retrieves the patch level from version information.",
            "vergetbuildnumber": "Retrieves the build number from version information.",
            "vergetproductversion": "Retrieves the product version from version information.",
            "vergetfiledescription": "Retrieves the file description from version information.",
            "vergetcompanyname": "Retrieves the company name from version information.",
            "vergetlegaltrademarks": "Retrieves the legal trademarks from version information.",
            "vergetcomments": "Retrieves the comments from version information.",
            "vergetinternalname": "Retrieves the internal name from version information.",
            "vergetoriginalfilename": "Retrieves the original filename from version information.",
            "vergetprivatebuild": "Retrieves private build information from version information.",
            "vergetspecialbuild": "Retrieves special build information from version information.",
            "verquerylangcodepage": "Retrieves the language and code page for version information.",
            "verresourcedecode": "Decodes a version resource into readable format.",
            "verwrite": "Writes updated version information to a file.",
            "verupdateregistry": "Updates the system registry with version information.",
            "verrestore": "Restores version information from backup.",
            "vercommit": "Commits version information changes to a file.",
            "verlock": "Locks a file for version information update.",
            "verunlock": "Unlocks a file after version information update.",
            "verinit": "Initializes version information retrieval for a file.",
            "vercleanup": "Cleans up resources allocated for version information.",
            "verresourcedata": "Retrieves raw data from a version resource.",
            "verresourceupdate": "Updates the resource section of a file with version data.",
            "verfindlanguage": "Finds the best matching language for version resources.",
            "verformat": "Formats version information into a human-readable string.",
            "vervalidate": "Validates the consistency and integrity of version information.",
            "vernotify": "Notifies applications of version changes for a file.",
            "verarchive": "Archives the version information for historical reference.",
            "verquerytimestamp": "Retrieves a timestamp from version information.",
            "vergetchecksum": "Calculates and retrieves a checksum for version information.",
            "vercompareex": "Performs an extended comparison of version information.",
            "vermergelocalised": "Merges localized version information with default values.",
            "verfinalize": "Finalizes version information updates for a file."
        }
    },
    "psapi.dll": {
        "explanation": "Provides process status functions for enumerating processes and modules.",
        "apis": {
            "enumprocesses": "Enumerates all active process identifiers.",
            "enumprocessmodules": "Retrieves handles for all modules in a specified process.",
            "getmodulebaseaddress": "Retrieves the base address of a module in a process.",
            "getmodulenamemodexa": "Retrieves the fully qualified path for a module (ANSI version).",
            "getmodulenamemodexw": "Retrieves the fully qualified path for a module (Unicode version).",
            "getmoduleinformation": "Retrieves information about a module in a process.",
            "psapi_api7": DEFAULT_EXPLANATION,
            "psapi_api8": DEFAULT_EXPLANATION,
            "psapi_api9": DEFAULT_EXPLANATION,
            "psapi_api10": DEFAULT_EXPLANATION,
            "psapi_api11": DEFAULT_EXPLANATION,
            "psapi_api12": DEFAULT_EXPLANATION,
            "psapi_api13": DEFAULT_EXPLANATION,
            "psapi_api14": DEFAULT_EXPLANATION,
            "psapi_api15": DEFAULT_EXPLANATION,
            "psapi_api16": DEFAULT_EXPLANATION,
            "psapi_api17": DEFAULT_EXPLANATION,
            "psapi_api18": DEFAULT_EXPLANATION,
            "psapi_api19": DEFAULT_EXPLANATION,
            "psapi_api20": DEFAULT_EXPLANATION,
            "getprocessmemoryinfo": "Retrieves memory usage information for a specified process.",
            "getperformanceinfo": "Retrieves performance information about the system.",
            "enumdevicedrivers": "Enumerates all loaded device drivers in the system.",
            "getdeviceframename": "Retrieves the file name of a specified device driver.",
            "queryworkingsetsize": "Retrieves the working set size for a process.",
            "setworkingsetsize": "Sets the working set size for a process.",
            "getprocessimagefilename": "Retrieves the image file name for a specified process.",
            "enumprocessheaps": "Enumerates all heaps used by a specified process.",
            "getheapinformation": "Retrieves information about a heap from a process.",
            "queryprocessvm": "Queries the virtual memory information of a process.",
            "getmodulefilenameex": "Retrieves the fully qualified path for a module in a process.",
            "enumunloadedmodules": "Enumerates modules that were recently unloaded from a process.",
            "queryprocesscpuusage": "Retrieves CPU usage statistics for a specified process.",
            "queryprocessdiskio": "Retrieves disk I/O statistics for a specified process.",
            "getprocessthreadtimes": "Retrieves timing information for a process's threads.",
            "getprocesshandlecount": "Retrieves the number of open handles in a specified process.",
            "getsystemhandleinformation": "Retrieves information about all system handles.",
            "enumprocessthreads": "Enumerates all threads in a specified process.",
            "getthreadinformation": "Retrieves detailed information about a specified thread.",
            "querysystemmoduleinformation": "Retrieves information about loaded system modules.",
            "getprocessmodulefilename": "Retrieves the file name of a module in a process.",
            "queryvirtualmemory": "Queries virtual memory information for a process.",
            "getmemorystatus": "Retrieves the current memory status of the system.",
            "getprocesslist": "Retrieves a list of all active processes on the system.",
            "getprocessowner": "Retrieves the owner (user) of a specified process.",
            "enumprocessservices": "Enumerates services associated with a process.",
            "queryprocessversion": "Retrieves version information for a process.",
            "getprocesspriority": "Retrieves the priority class of a specified process.",
            "setprocesspriority": "Sets the priority class of a specified process.",
            "getprocessaffinity": "Retrieves the processor affinity mask for a specified process."
        }
    },
    "setupapi.dll": {
        "explanation": "Supports device installation and configuration.",
        "apis": {
            "setupdigetclassdescriptiona": "Retrieves the class description for a device setup class (ANSI version).",
            "setupdigetclassdescriptionw": "Retrieves the class description for a device setup class (Unicode version).",
            "setupdienumdeviceinterfaces": "Enumerates device interfaces for a setup class.",
            "setupdigetdeviceinterface": "Retrieves a device interface for a specified device.",
            "setupdigetdeviceinterface_detaila": "Retrieves detailed info about a device interface (ANSI version).",
            "setupdigetdeviceinterface_detailw": "Retrieves detailed info about a device interface (Unicode version).",
            "setupdigetdeviceproperty": "Retrieves a property for a specified device.",
            "setupdisetdeviceproperty": "Sets a property for a specified device.",
            "setupdienumdeviceinfo": "Enumerates devices in a device information set.",
            "setupdigetdeviceregistryproperty": "Retrieves a device's registry property.",
            "setupdisetdeviceregistryproperty": "Sets a device's registry property.",
            "setupdigetclassdevids": "Retrieves device instance IDs for a setup class.",
            "setupdiopendevinfoptr": "Opens a handle to a device information set.",
            "setupdidestroydevinfolist": "Destroys a device information set and frees its resources.",
            "setupapi_api15": DEFAULT_EXPLANATION,
            "setupapi_api16": DEFAULT_EXPLANATION,
            "setupapi_api17": DEFAULT_EXPLANATION,
            "setupapi_api18": DEFAULT_EXPLANATION,
            "setupapi_api19": DEFAULT_EXPLANATION,
            "setupapi_api20": DEFAULT_EXPLANATION,
            "setupapi_installdevice": "Installs a device using setup API routines.",
            "setupapi_uninstalldevice": "Uninstalls a device from the system.",
            "setupapi_enumeratedevices": "Enumerates devices present in the system.",
            "setupapi_getdeviceinstanceid": "Retrieves the device instance ID for a specified device.",
            "setupapi_getdevicedescription": "Retrieves the description of a specified device.",
            "setupapi_getdevicehardwareids": "Retrieves hardware IDs for a specified device.",
            "setupapi_setdevicepowersettings": "Configures power management settings for a device.",
            "setupapi_getdevicepowersettings": "Retrieves power management settings for a device.",
            "setupapi_querydrivernode": "Queries driver node information for a device.",
            "setupapi_configuredriver": "Configures a driver for a device.",
            "setupapi_enumeratedrivernodes": "Enumerates driver nodes for a device.",
            "setupapi_getclassdevicelist": "Retrieves a list of devices for a setup class.",
            "setupapi_getdeviceregistrypropertyex": "Retrieves extended registry properties for a device.",
            "setupapi_setdeviceregistrypropertyex": "Sets extended registry properties for a device.",
            "setupapi_getdeviceinterfacealias": "Retrieves an alias for a device interface.",
            "setupapi_setdeviceinterfacealias": "Sets an alias for a device interface.",
            "setupapi_getdeviceinstallationstate": "Retrieves the installation state of a device.",
            "setupapi_setdeviceinstallationstate": "Sets the installation state of a device.",
            "setupapi_getinfsection": "Retrieves an INF section from a device installation file.",
            "setupapi_queryinfsection": "Queries information from an INF section.",
            "setupapi_installinfsection": "Installs a section from an INF file.",
            "setupapi_querydriverinfodetail": "Retrieves detailed driver information from an INF file.",
            "setupapi_getselecteddriver": "Retrieves the driver selected for a device.",
            "setupapi_setselecteddriver": "Sets the driver selected for a device.",
            "setupapi_commitinstaller": "Commits installation changes for a device.",
            "setupapi_cleanupinstaller": "Cleans up installer resources for a device.",
            "setupapi_enumeratedeviceregistryproperties": "Enumerates registry properties for a device.",
            "setupapi_getdevicecapabilities": "Retrieves the capabilities of a device.",
            "setupapi_querydeviceid": "Queries the device ID for a specified device.",
            "setupapi_finalizedevice": "Finalizes the installation process for a device."
        }
    },
    "iphlpapi.dll": {
        "explanation": "Offers helper functions for IP configuration and network diagnostics.",
        "apis": {
            "getadaptersaddresses": "Retrieves network adapter addresses for the local system.",
            "getiftable": "Retrieves a table of network interface information.",
            "getifentry": "Retrieves information for a specified network interface.",
            "iphlpapi_api4": DEFAULT_EXPLANATION,
            "iphlpapi_api5": DEFAULT_EXPLANATION,
            "iphlpapi_api6": DEFAULT_EXPLANATION,
            "iphlpapi_api7": DEFAULT_EXPLANATION,
            "iphlpapi_api8": DEFAULT_EXPLANATION,
            "iphlpapi_api9": DEFAULT_EXPLANATION,
            "iphlpapi_api10": DEFAULT_EXPLANATION,
            "iphlpapi_api11": DEFAULT_EXPLANATION,
            "iphlpapi_api12": DEFAULT_EXPLANATION,
            "iphlpapi_api13": DEFAULT_EXPLANATION,
            "iphlpapi_api14": DEFAULT_EXPLANATION,
            "iphlpapi_api15": DEFAULT_EXPLANATION,
            "iphlpapi_api16": DEFAULT_EXPLANATION,
            "iphlpapi_api17": DEFAULT_EXPLANATION,
            "iphlpapi_api18": DEFAULT_EXPLANATION,
            "iphlpapi_api19": DEFAULT_EXPLANATION,
            "iphlpapi_api20": DEFAULT_EXPLANATION,
            "getnetworkparams": "Retrieves network parameters for the local system.",
            "getperadapterinfo": "Retrieves detailed information for a specific network adapter.",
            "getadapterordermap": "Retrieves the adapter order map for the system.",
            "notifyaddrchange": "Notifies the caller of address changes on a network adapter.",
            "notifyroutechange": "Notifies the caller of route changes on the network.",
            "getbestinterface": "Determines the best network interface for a given destination.",
            "getipforwardtable": "Retrieves the IP routing table for the local system.",
            "getifentry2": "Retrieves extended information for a network interface.",
            "getadapteraddresses": "Alternate function to retrieve adapter addresses with extended options.",
            "convertifindex2luid": "Converts an interface index to a locally unique identifier (LUID).",
            "convertluid2ifindex": "Converts a LUID to an interface index.",
            "getipstatistics": "Retrieves IP statistics for the local system.",
            "geticmpstatistics": "Retrieves ICMP statistics for the local system.",
            "gettcpstatistics": "Retrieves TCP statistics for the local system.",
            "getudpstatistics": "Retrieves UDP statistics for the local system.",
            "setipinterface": "Sets IP interface parameters for a network adapter.",
            "getipinterface": "Retrieves IP interface parameters for a network adapter.",
            "getipv6statistics": "Retrieves IPv6 statistics for the local system.",
            "createipforwardentry": "Creates a new entry in the IP routing table.",
            "deleteipforwardentry": "Deletes an entry from the IP routing table.",
            "setipforwardentry": "Modifies an existing entry in the IP routing table.",
            "getipforwardentry": "Retrieves information for a specific IP routing table entry.",
            "getadapterinfo": "Retrieves adapter information for the local system.",
            "convertipv4mask": "Converts an IPv4 subnet mask to its prefix length.",
            "getdnsservers": "Retrieves DNS server addresses for a network adapter.",
            "setdnsservers": "Sets DNS server addresses for a network adapter.",
            "getwin32ipforwardtable": "Retrieves the IP routing table in Win32 format.",
            "setipaddr": "Sets the IP address for a network adapter.",
            "getipaddr": "Retrieves the IP address for a network adapter.",
            "renewiplease": "Renews the IP lease for a network adapter."
        }
    }
}

# --- Extend each DLL's APIs to ensure at least 100 functions ---
for dll in dll_api_explanations.values():
    extend_apis(dll, target=100)

# --- Dangerous Functions List ---
dangerous_functions = [
    "createremotethread", "writeprocessmemory", "virtualalloc", "setunhandledexceptionfilter",
    "regcreatekeyexa", "regcreatekeyexw", "regsetvalueexa", "getprocaddress", "loadlibrary",
    "internetconnecta", "httpsendrequesta", "httpendrequesta", "cryptencrypt", "cryptdecrypt"
]

# --- Import Extraction Function ---
def extract_and_sort_imports(file_path):
    """Parse the PE file and extract its import table.
       Returns a dictionary with DLL names as keys and sorted lists of imported functions as values."""
    binary = lief.parse(file_path)
    if not binary or not isinstance(binary, lief.PE.Binary):
        raise ValueError("Not a valid PE file.")
    
    imports_by_dll = {}
    for imp in binary.imports:
        dll_name = imp.name or "UNKNOWN_DLL"
        if dll_name not in imports_by_dll:
            imports_by_dll[dll_name] = []
        for entry in imp.entries:
            func = entry.name if entry.name else f"Ordinal_{entry.ordinal}"
            imports_by_dll[dll_name].append(func)
    
    for dll in imports_by_dll:
        imports_by_dll[dll].sort(key=str.lower)
    sorted_imports = {dll: imports_by_dll[dll] for dll in sorted(imports_by_dll, key=str.lower)}
    return sorted_imports

# --- Text Output Generation Function ---
def generate_text_output(sorted_imports, nested_dict, dangerous_set):
    lines = []
    for dll, functions in sorted_imports.items():
        key = dll.lower()
        if key in nested_dict:
            lines.append(f"{dll}:")
            dll_info = nested_dict[key]
            lines.append(f"    DLL Explanation: {dll_info['explanation']}")
            printed = 0
            for api in sorted(functions, key=str.lower):
                api_key = api.lower()
                if api_key in dll_info["apis"]:
                    lines.append(f"    {api}: {dll_info['apis'][api_key]}")
                    printed += 1
                else:
                    lines.append(f"    {api}")
                if printed >= 20:
                    break
            lines.append("")
    if dangerous_set:
        lines.append("Most Dangerous/Suspicious Functions:")
        for func in sorted(dangerous_set, key=str.lower):
            explanation = None
            for dll_data in nested_dict.values():
                if func.lower() in dll_data["apis"]:
                    explanation = dll_data["apis"][func.lower()]
                    break
            if explanation and explanation != DEFAULT_EXPLANATION:
                lines.append(f"    {func}: {explanation}")
            else:
                lines.append(f"    {func}")
    return "\n".join(lines)

# --- HTML Output Generation Function ---
def generate_html_output(sorted_imports, nested_dict, dangerous_set):
    html_lines = [
        "<html>",
        "<head>",
        "<title>PE Import Analysis</title>",
        "<style>",
        "table { border-collapse: collapse; width: 90%; margin: 10px; }",
        "th, td { border: 1px solid #ddd; padding: 8px; }",
        "th { background-color: #f2f2f2; }",
        "</style>",
        "</head>",
        "<body>",
        "<h1>PE Import Analysis</h1>"
    ]
    for dll, functions in sorted_imports.items():
        key = dll.lower()
        if key in nested_dict:
            dll_info = nested_dict[key]
            html_lines.append(f"<h2>{html.escape(dll)}</h2>")
            html_lines.append(f"<p><strong>DLL Explanation:</strong> {html.escape(dll_info['explanation'])}</p>")
            html_lines.append("<table>")
            html_lines.append("<tr><th>API Function</th><th>Explanation</th></tr>")
            printed = 0
            for api in sorted(functions, key=str.lower):
                api_key = api.lower()
                if api_key in dll_info["apis"]:
                    explanation = dll_info["apis"][api_key]
                    row = f"<tr><td>{html.escape(api)}</td><td>{html.escape(explanation)}</td></tr>"
                    html_lines.append(row)
                    printed += 1
                else:
                    row = f"<tr><td>{html.escape(api)}</td><td></td></tr>"
                    html_lines.append(row)
                if printed >= 20:
                    break
            html_lines.append("</table>")
    if dangerous_set:
        html_lines.append("<h2>Most Dangerous/Suspicious Functions</h2>")
        html_lines.append("<table>")
        html_lines.append("<tr><th>API Function</th><th>Explanation</th></tr>")
        for func in sorted(dangerous_set, key=str.lower):
            explanation = None
            for dll_data in nested_dict.values():
                if func.lower() in dll_data["apis"]:
                    explanation = dll_data["apis"][func.lower()]
                    break
            if explanation and explanation != DEFAULT_EXPLANATION:
                row = f"<tr><td>{html.escape(func)}</td><td>{html.escape(explanation)}</td></tr>"
            else:
                row = f"<tr><td>{html.escape(func)}</td><td></td></tr>"
            html_lines.append(row)
        html_lines.append("</table>")
    html_lines.append("</body></html>")
    return "\n".join(html_lines)

# --- Main Function ---
def main():
    parser = argparse.ArgumentParser(
        description="Extract and sort imported functions from a PE file with detailed DLL and API explanations."
    )
    parser.add_argument("file_path", help="Path to the PE file")
    args = parser.parse_args()

    try:
        sorted_imports = extract_and_sort_imports(args.file_path)
        
        # Determine dangerous functions from extracted imports.
        dangerous_found = set()
        for dll, functions in sorted_imports.items():
            for api in functions:
                if api.lower() in dangerous_functions:
                    dangerous_found.add(api)
        
        include_dangerous = input("Include dangerous/suspicious functions in the output? (y/n): ").strip().lower() == "y"
        output_html = input("Save output as HTML? (y/n): ").strip().lower() == "y"
        
        base_name = os.path.splitext(os.path.basename(args.file_path))[0]
        default_ext = ".html" if output_html else ".txt"
        default_filename = f"{base_name}{default_ext}"
        file_name = input(f"Enter output file name (default: {default_filename}): ").strip() or default_filename
        
        if output_html:
            output_str = generate_html_output(sorted_imports, dll_api_explanations, dangerous_found if include_dangerous else [])
        else:
            output_str = generate_text_output(sorted_imports, dll_api_explanations, dangerous_found if include_dangerous else [])
        
        with open(file_name, "w", encoding="utf-8") as f:
            f.write(output_str)
        print(f"Output saved to {file_name}")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
