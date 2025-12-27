import requests
import socket
from tabulate import tabulate
from time import sleep
from Core import listener, color, database
import ipaddress  # Import ipaddress module for IP address validation
from Core.color import cyan, yellow, green, red 

def StartListener(command, conn):
    try:
        command = command.split()

        try:
            listener_name = command[2]
            listener_ip = command[3]  # Expecting the user to provide an IP address
            listener_port = command[4]

            # Validate the IP address
            ipaddress.ip_address(listener_ip)  # This will raise an error if invalid

            results = database.return_token(conn, listener_name)

            if not results:
                res = database.start_listener(conn, listener_ip, listener_port, listener_name)

                if res:
                    try:
                        listener.start(listener_ip, listener_port)
                        sleep(0.5)

                    except Exception as e:
                        print("[%s] Cannot start the listener on %s:%s: %s" % (color.red("-"), listener_ip, listener_port, str(e)))
            else:
                print("[%s] %s Listener found!!" % (color.red("-"), listener_name))

        except ValueError:
            print("[%s] Invalid IP address or parameters." % color.red("-"))

    except Exception as e:
        print("[%s] There was an error found: %s" % (color.red("-"), str(e)))

def StopListener(command, conn):
    try:
        name = command.split()[2]
        results = database.return_token(conn, name)

        if results:
            for i in range(len(results)):
                try:
                    url = "http://%s:%s/shutdown/%s/%s" % (results[i][1], results[i][2], name, results[i][0])
                    req = requests.get(url)

                    if int(req.status_code) == 200:
                        print("[%s] %s Listener stopped" % (color.green("+"), name))
                        database.delete_listener(conn, results[i][0])
                        print("[%s] %s Listener deleted" % (color.green("+"), name))

                except Exception as e:
                    print("[%s] %s Listener is not running, run the listener first: %s" % (color.red("-"), name, str(e)))
        else:
            print("[%s] %s Listener found!!" % (color.red("-"), name))

    except Exception as e:
        print("[%s] There was an error found: %s" % (color.red("-"), str(e)))

def ReloadListener(conn):
    results = database.run_listener(conn)

    if results:
        for i in range(len(results)):
            listener.start(results[i][0], results[i][1])
            sleep(0.5)

        print("[%s] Listeners are up" % color.green("+"))
    else:
        print("[%s] Database has no listeners yet!" % color.red("-"))

def ListListener(conn):
    # Assuming `database.list_listener(conn)` returns a list of listeners
    results = database.list_listener(conn)
    
    data = []
    
    # Appending results to data with color formatting
    for i in range(len(results)):
        data.append([
            cyan(results[i][0]),           # Listener Name (assumed to be a string)
            yellow(results[i][1]),         # Listener IP (assumed to be a string)
            green(str(results[i][2]))      # Listener Port (converted to a string)
        ])
    
    # Printing the formatted table with colored headers and column alignment
    print(tabulate(data, headers=[red("Listener Name"), red("Listener IP"), red("Listener Port")], tablefmt="fancy_grid", colalign=("left", "left", "right")), "\n")
