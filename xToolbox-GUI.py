import tkinter as tk
from tkinter import Message, filedialog, ttk
import os, sys, shutil, csv, time, ipinfo, datetime, pprint, threading, re
from tkinter.constants import DISABLED

## Function setup ## 

def workerThread(tasks):
    """This function runs on another thread to keep GUI responsive, its only purpose is to run other functions, one after another"""
    for task in tasks:
        if task == 'renameFolders':
            renameFolders()
        elif task == 'convertPcap':
            convertPcap()
        elif task == 'parseCsv':
            parseCsv()
        elif task == 'createIpDatabase':
            createIpDatabase()
        elif task == 'createHistogram':
            createHistogram()
    output_window.insert('end', 'Tasks complete!' + '\n')
    output_window.see(tk.END)

def browseButton():
    """Button to open a window for directory selection."""
    global folder_path
    selected_directory = filedialog.askdirectory(initialdir='/')
    folder_path.set(selected_directory)

def printOptions():
    """'Print' out selected options"""
    now = datetime.datetime.now().strftime("%H:%M:%S")
    output_window.insert('end', now + '\n')

    user_directory = folder_path.get()
    if user_directory == '':
        output_window.insert('end', 'No directory provided!' + '\n')
        return
    
    output_window.insert('end','Folder: ' + user_directory + '\n')

    user_rename_pcap_folders = rename_pcap_folders.get()
    if user_rename_pcap_folders == 1:
        user_rename_pcap_folders = "Yes"
    else:
        user_rename_pcap_folders = "No"
    output_window.insert('end','Rename folders: ' + user_rename_pcap_folders + '\n')

    user_convert_pcap_files = convert_pcap_files.get()
    if user_convert_pcap_files == 1:
        user_convert_pcap_files = "Yes"
    else:
        user_convert_pcap_files = "No"
    output_window.insert('end','Convert pcap files: ' + user_convert_pcap_files + '\n')

    user_parse_csv = parse_csv.get()
    if user_parse_csv == 1:
        user_parse_csv = "Yes"
    else:
        user_parse_csv = "No"
    output_window.insert('end','Parse csv: ' + user_parse_csv + '\n')
    if user_parse_csv == "Yes":
        user_host_ipv4 = ipv4_entry.get()
        user_host_ipv6 = ipv6_entry.get()
        output_window.insert('end', '\t' + 'Host IPv4: ' + user_host_ipv4 + '\n')
        output_window.insert('end', '\t' + 'Host IPv6: ' + user_host_ipv6 + '\n')

    user_create_database = create_database.get()
    if user_create_database == 1:
        user_create_database = "Yes"
    else:
        user_create_database = "No"
    output_window.insert('end','Create IP database: ' + user_create_database + '\n')
    
    user_create_histogram = create_histogram.get()
    if user_create_histogram == 1:
        user_create_histogram = "Yes"
    else:
        user_create_histogram = "No"
    output_window.insert('end', 'Create histogram: ' + user_create_histogram + '\n')

    tasks = []

    # Call functions based on user options
    if user_rename_pcap_folders == "Yes":
        tasks.append('renameFolders')
    if user_convert_pcap_files == "Yes":
        tasks.append('convertPcap')
    if user_parse_csv == "Yes":
        tasks.append('parseCsv')
    if user_create_database == "Yes":
        tasks.append('createIpDatabase')
    if user_create_histogram == "Yes":
        tasks.append('createHistogram')

    threading.Thread(target=workerThread, args=(tasks,)).start()

def renameFolders():
    output_window.insert('end', '-'*15 + '\nRenaming folders..' + '\n')
    working_dir = folder_path.get()
    os.chdir(working_dir)
    working_dir_folders = os.listdir()

    pcap_folders = []
    pcap_files = []

    for folder in working_dir_folders:
        if folder.endswith('.1'):
            pcap_folders.append(folder)

    if len(pcap_folders) == 0:
        output_window.insert('end', 'Found no \'.1\' folder(s)')
        return()

    for files in pcap_folders:
        os.chdir(files)
        tmp_files = os.listdir()
        for tmp_file in tmp_files:
            if tmp_file.endswith('.1'):
                pcap_files.append(os.path.abspath(tmp_file))
        os.chdir(working_dir)

    for files in pcap_files:
        """Renaming .pcap.1 -> .pcap"""
        output_window.insert('end', 'renaming file: ' + files + '\n')
        output_window.see(tk.END)
        root.update_idletasks()
        shutil.move(files, files[:-2])
        time.sleep(0.5)
        shutil.move(files[:-2], working_dir)
        time.sleep(0.5)

    for folder in pcap_folders:
        """Removing old folders"""
        output_window.insert('end', 'removing folder: ' + folder + '\n')
        output_window.see(tk.END)
        root.update_idletasks()
        os.rmdir(os.path.abspath(folder))
        time.sleep(0.5)
    return()

def convertPcap():
    """Convert .pcap files to .csv files"""
    output_window.insert('end', '-'*15 + '\nConverting files....' + '\n')
    working_dir = folder_path.get()
    os.chdir(working_dir)

    files_to_convert = []
    files_in_folder = os.listdir()

    for file in files_in_folder:
        if file.endswith('.pcap'):
            files_to_convert.append(os.path.abspath(file))

    progress = 1
    total = len(files_to_convert)

    for files in files_to_convert:
        file_size = os.path.getsize(files)
        if file_size >= 1000*1000*1000:
            file_size = round(file_size / (1000*1000*1000),2)
            file_size = str(file_size) + " GB"
        elif file_size >= 1000*1000:
            file_size = round(file_size / (1000*1000),2)
            file_size = str(file_size) + " MB"
        elif file_size >= 1000:
            file_size = round(file_size / 1000,2)
            file_size = str(file_size) + " kB"
        now = datetime.datetime.now().strftime("%H:%M:%S")
        output_window.insert('end', '[' + now + '] Converting file ' + str(progress) + ' of ' + str(total) + ' (' + file_size + ')\n')
        output_window.see(tk.END)
        csv_file_name = files[:-5] + '.csv'
        print("tshark -r " + files + " -T fields -e frame.number -e _ws.col.Source -e _ws.col.Destination -e frame.len -e frame.time -e litecoin.command -E header=y -E separator=; > " + csv_file_name)
        os.system("tshark -r " + files + " -T fields -e frame.number -e _ws.col.Source -e _ws.col.Destination -e frame.len -e frame.time -e litecoin.command -E header=y -E separator=; > " + csv_file_name)
        root.update_idletasks()
        progress += 1
    output_window.insert('end', 'Done!' + '\n')
    output_window.see(tk.END)
    root.update_idletasks()
    return()

def parseCsv():
    """Extract messages in MiB from .csv files (resultfile.csv) and create a list of ip-addresses (ip-addresses.txt)"""
    output_window.insert('end', '-'*15 + '\nParsing csv files..' + '\n')
    data_table = {
        'version'       : {'sent': 0, 'received': 0, 'total': 0},
        'verack'        : {'sent': 0, 'received': 0, 'total': 0},
        'addr'          : {'sent': 0, 'received': 0, 'total': 0},
        'inv'           : {'sent': 0, 'received': 0, 'total': 0},
        'getdata'       : {'sent': 0, 'received': 0, 'total': 0},
        'merkleblock'   : {'sent': 0, 'received': 0, 'total': 0},
        'getblocks'     : {'sent': 0, 'received': 0, 'total': 0},
        'getheaders'    : {'sent': 0, 'received': 0, 'total': 0},
        'tx'            : {'sent': 0, 'received': 0, 'total': 0},
        'headers'       : {'sent': 0, 'received': 0, 'total': 0},
        'block'         : {'sent': 0, 'received': 0, 'total': 0},
        'getaddr'       : {'sent': 0, 'received': 0, 'total': 0},
        'mempool'       : {'sent': 0, 'received': 0, 'total': 0},
        'ping'          : {'sent': 0, 'received': 0, 'total': 0},
        'pong'          : {'sent': 0, 'received': 0, 'total': 0},
        'notfound'      : {'sent': 0, 'received': 0, 'total': 0},
        'filterload'    : {'sent': 0, 'received': 0, 'total': 0},
        'filteradd'     : {'sent': 0, 'received': 0, 'total': 0},
        'filterclear'   : {'sent': 0, 'received': 0, 'total': 0},
        'reject'        : {'sent': 0, 'received': 0, 'total': 0},
        'sendheaders'   : {'sent': 0, 'received': 0, 'total': 0},
        'feefilter'     : {'sent': 0, 'received': 0, 'total': 0},
        'sendcmpct'     : {'sent': 0, 'received': 0, 'total': 0},
        'cmpctblock'    : {'sent': 0, 'received': 0, 'total': 0},
        'getblocktxn'   : {'sent': 0, 'received': 0, 'total': 0},
        'blocktxn'      : {'sent': 0, 'received': 0, 'total': 0}
    }
    ip_table = [

    ]
    used_files = [
    'histogram.csv',
    'inbound-to-outbound-stats.csv',
    'ip-database.csv',
    'ipv4-to-ipv6-stats.csv',
    'resultfile.csv'
    ]

    traffic_by_protocol = {
    'ipv4': 0,
    'ipv6': 0
    }
    traffic_by_direction = {
    'inbound' : 0,
    'outbound': 0
    }
    command_table = {
    'version'       : 0,
    'verack'        : 0,
    'addr'          : 0,
    'inv'           : 0,
    'getdata'       : 0,
    'merkleblock'   : 0,
    'getblocks'     : 0,
    'getheaders'    : 0,
    'tx'            : 0,
    'headers'       : 0,
    'block'         : 0,
    'getaddr'       : 0,
    'mempool'       : 0,
    'ping'          : 0,
    'pong'          : 0,
    'notfound'      : 0,
    'filterload'    : 0,
    'filteradd'     : 0,
    'filterclear'   : 0,
    'reject'        : 0,
    'sendheaders'   : 0,
    'feefilter'     : 0,
    'sendcmpct'     : 0,
    'cmpctblock'    : 0,
    'getblocktxn'   : 0,
    'blocktxn'      : 0
    }
    csv_files = []
    working_directory = folder_path.get()
    host_ipv4_address = ipv4_entry.get()
    if host_ipv4_address != '':
        host_ipv4_address = host_ipv4_address.strip()
        ip_table.append(host_ipv4_address)
    host_ipv6_address = ipv6_entry.get()
    if host_ipv6_address != '':
        host_ipv6_address = host_ipv6_address.strip()
        ip_table.append(host_ipv6_address)

    os.chdir(working_directory)
    files_in_working_directory = os.listdir()

    for file in files_in_working_directory:
        if file.endswith('.csv') and file not in used_files:
            csv_files.append(os.path.abspath(file))
    
    if len(host_ipv4_address) == 0 and len(host_ipv6_address) == 0:
        output_window.insert('end', 'Must have either IPv4 or IPv6 address!' + '\n')
        output_window.see(tk.END)
        return()
    
    progress = 1
    line_count = 0
    total_count = 0
    skip_line = True
    total = len(csv_files)

    for file in csv_files:
        file_size = os.path.getsize(file)
        if file_size >= 1000*1000*1000:
            file_size = round(file_size / (1000*1000*1000),2)
            file_size = str(file_size) + " GB"
        elif file_size >= 1000*1000:
            file_size = round(file_size / (1000*1000),2)
            file_size = str(file_size) + " MB"
        elif file_size >= 1000:
            file_size = round(file_size / 1000,2)
            file_size = str(file_size) + " kB"
        now = datetime.datetime.now().strftime("%H:%M:%S")
        output_window.insert('end', '[' + now + '] Parsing file ' + str(progress) + ' of ' + str(total) + ' (' + file_size + ')\n')
        output_window.see(tk.END)
        root.update_idletasks()
        with open(file, mode='r') as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=';')
            for row in csv_reader:
                if line_count == 0:
                    line_count += 1
                    total_count += 1
                    continue
                else:
                    if row[1] == host_ipv4_address or row[1] == host_ipv6_address:
                        traffic_by_direction['outbound'] += int(row[3])
                    else:
                        traffic_by_direction['inbound'] += int(row[3])
                    if row[5] != '':
                        command_table[row[5]] += 1
                    if re.search('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', row[1]) != None:
                        traffic_by_protocol['ipv4'] += int(row[3])
                    else:
                        traffic_by_protocol['ipv6'] += int(row[3])
                    if row[1] != host_ipv4_address and row[1] != host_ipv6_address:
                        if row[1] not in ip_table:
                            ip_table.append(row[1])
                    if skip_line and row[5] == '':
                        line_count += 1
                        total_count += 1
                        continue
                    else:
                        skip_line = False
                        if row[3] == '66':
                            line_count += 1
                            total_count += 1
                            continue
                        else:
                            if row[5] != '':
                                command = row[5]
                                if row[1] == host_ipv4_address or row[1] == host_ipv6_address:

                                    data_table[command]['sent'] += int(row[3])
                                else:
                                    data_table[command]['received'] += int(row[3])
                            else:
                                if row[1] == host_ipv4_address or row[1] == host_ipv6_address:
                                    data_table[command]['sent'] += int(row[3])
                                else:
                                    data_table[command]['received'] += int(row[3])
                            line_count += 1
                            total_count += 1
        line_count = 0
        progress += 1
    
    for item in data_table:
        data_table[item]['total'] = data_table[item]['sent'] + data_table[item]['received']
    
    for item in data_table:
        data_table[item]['sent'] = round(data_table[item]['sent'] / (1024*1024),2)
        data_table[item]['received'] = round(data_table[item]['received'] / (1024*1024),2)
        data_table[item]['total'] = round(data_table[item]['total'] / (1024*1024),2)

    for item in traffic_by_direction:
        traffic_by_direction[item] = round(traffic_by_direction[item] / (1024*1024),2)

    for item in traffic_by_protocol:
        traffic_by_protocol[item] = round(traffic_by_protocol[item] / (1024*1024),2)

    output_window.insert('end', 'Processed ' + str(total_count) + ' lines' + '\n')
    output_window.see(tk.END)
    root.update_idletasks()

    output_window.insert('end', 'Writing resultfile.csv' + '\n')
    output_window.see(tk.END)
    root.update_idletasks()

    with open('resultfile.csv', mode='w', newline='', encoding='utf-8') as output_file:
        csv_writer = csv.writer(output_file, delimiter=';')
        csv_writer.writerow(['Message', 'Sent (MiB)', 'Received (MiB)', 'Total (Mib)'])
        for ltc_message, messageMiBs in data_table.items():
            numbers = []
            for key in messageMiBs:
                numbers.append(messageMiBs[key])
            csv_writer.writerow([ltc_message, numbers[0], numbers[1], numbers[2]])

    output_window.insert('end', 'Writing ip-addresses.txt' + '\n')
    output_window.see(tk.END)
    root.update_idletasks()

    with open('ip-addresses.txt', mode='w', encoding='utf-8', newline='\n') as output_file:
        for address in ip_table:
            output_file.write(address + '\n')

    output_window.insert('end', 'Writing ipv4-ipv6-stats.csv' + '\n')
    output_window.see(tk.END)
    root.update_idletasks()

    with open('ipv4-ipv6-stats.csv', mode='w', encoding='utf8', newline='') as output_file:
        csv_writer = csv.writer(output_file, delimiter=';')
        csv_writer.writerow(['Protocol', 'MiB'])
        for item in traffic_by_protocol:
            csv_writer.writerow([item, traffic_by_protocol[item]])

    output_window.insert('end', 'Writing inbound-to-outbound-stats.csv' + '\n')
    output_window.see(tk.END)
    root.update_idletasks()

    with open('inbound-to-outbound-stats.csv', mode='w', newline='', encoding='utf8') as output_file:
        csv_writer = csv.writer(output_file, delimiter=';')
        csv_writer.writerow(['Direction', 'MiB'])
        for item in traffic_by_direction:
            csv_writer.writerow([item, traffic_by_direction[item]])

    output_window.insert('end', 'Writing litecoin-commands-stats.csv' + '\n')
    output_window.see(tk.END)
    root.update_idletasks()

    with open('litecoin-commands-stats.csv', mode='w', newline='', encoding='utf-8') as outpupt_file:
        csv_writer = csv.writer(outpupt_file, delimiter=';')
        csv_writer.writerow(['Message', 'Amount'])
        for item in command_table:
            csv_writer.writerow([item, command_table[item]])
    return

def createIpDatabase():
    """Create a IP 'database' using IPinfo.io"""
    output_window.insert('end', '-'*15 + '\nCreating IP-database..' + '\n')
    ip_address_file = 'ip-addresses.txt'
    ip_address_list = []
    ip_address_database = {}
    working_directory = folder_path.get()
    token = access_token_entry.get()

    if len(token) == 0:
        output_window.insert('end', 'No access token provided, aborting' + '\n')
        output_window.see(tk.END)
        return

    os.chdir(working_directory)

    handler = ipinfo.getHandler(access_token=token, request_options={'timeout': 10})

    with open(ip_address_file, mode='r') as input_file:
        for row in input_file:
            ip_address_list.append(row)

    output_window.insert('end', 'Performing lookup on ' + str(len(ip_address_list)) + ' IP addresses.' + '\n')
    output_window.see(tk.END)
    root.update_idletasks()

    for ip_address in ip_address_list:
        details = handler.getDetails(ip_address)
        ip_address_database[ip_address] = details.all
        try:
            details.hostname
        except AttributeError:
            ip_address_database[ip_address]['hostname'] = ''
        try:
            details.city
        except AttributeError:
            ip_address_database[ip_address]['city'] = ''
        try:
            details.region
        except AttributeError:
            ip_address_database[ip_address]['region'] = ''
        try:
            details.country
        except AttributeError:
            ip_address_database[ip_address]['country'] = ''
        try:
            details.loc
        except AttributeError:
            ip_address_database[ip_address]['loc'] = ''
        try:
            details.org
        except AttributeError:
            ip_address_database[ip_address]['org'] = ''
        try:
            details.postal
        except AttributeError:
            ip_address_database[ip_address]['postal'] = ''
        try:
            details.timezone
        except AttributeError:
            ip_address_database[ip_address]['timezone'] = ''
        try:
            details.country_name
        except AttributeError:
            ip_address_database[ip_address]['country_name'] = ''
        try:
            details.latitude
        except AttributeError:
            ip_address_database[ip_address]['latitude'] = ''
        try:
            details.longitude
        except AttributeError:
            ip_address_database[ip_address]['longitude'] = ''
        
        output_window.insert('end', '.')
        output_window.see(tk.END)
        root.update_idletasks()
    output_window.insert('end', '\nDone!\nWriting ip-databse.csv' + '\n')
    output_window.see(tk.END)
    root.update_idletasks()

    with open('ip-database.csv', mode='w', encoding='utf-8', newline='') as output_file:
        fieldnames = ['ip', 'hostname', 'city', 'region', 'country', 'loc', 'org', 'postal', 'timezone', 'country_name', 'latitude', 'longitude']
        csv_writer = csv.DictWriter(output_file, fieldnames=fieldnames, delimiter=';')
        csv_writer.writeheader()
        for entry in ip_address_database:
            csv_writer.writerow({'ip':ip_address_database[entry]['ip'],
            'hostname':ip_address_database[entry]['hostname'],
            'city':ip_address_database[entry]['city'],
            'region':ip_address_database[entry]['region'],
            'country':ip_address_database[entry]['country'],
            'loc':ip_address_database[entry]['loc'],
            'org':ip_address_database[entry]['org'],
            'postal':ip_address_database[entry]['postal'],
            'timezone':ip_address_database[entry]['timezone'],
            'country_name':ip_address_database[entry]['country_name'],
            'latitude':ip_address_database[entry]['latitude'],
            'longitude':ip_address_database[entry]['longitude']})
    
    output_window.insert('end', 'Done!' + '\n')
    output_window.see(tk.END)
    root.update_idletasks()

def createHistogram():
    """Create a histogram from csv files"""
    output_window.insert('end', '-'*15 + '\nCreating histogram..' + '\n')
    unrelated_files = [
    'litecoin-commands-stats.csv',
    'resultfile.csv',
    'inbound-to-outbound-stats.csv',
    'ipv4-ipv6-stats.csv',
    'ip-database.csv',
    'ip-addresses.txt']

    working_directory = folder_path.get()
    histogram_table = {}
    line_count = 0
    total_lines = 0
    file_count = 1

    os.chdir(working_directory)
    files = os.listdir()
    csv_files = []

    for file in files:
        if file.endswith('.csv'):
            if file not in unrelated_files:
                csv_files.append(file)
    
    if len(csv_files) == 0:
        output_window.insert('end', 'Did not find any .csv files, aborting' + '\n')
        output_window.see(tk.END)
        root.update_idletasks()
        return()
    
    total = len(csv_files)

    for csv_file in csv_files:
        file_size = os.path.getsize(csv_file)
        if file_size >= 1000*1000*1000:
            file_size = round(file_size / (1000*1000*1000),2)
            file_size = str(file_size) + " GB"
        elif file_size >= 1000*1000:
            file_size = round(file_size / (1000*1000),2)
            file_size = str(file_size) + " MB"
        elif file_size >= 1000:
            file_size = round(file_size / 1000,2)
            file_size = str(file_size) + " kB"
        now = datetime.datetime.now().strftime("%H:%M:%S")
        output_window.insert('end', '[' + now + '] Processing file ' + str(file_count) + ' of ' + str(total) + ' (' + file_size + ')' + '\n')
        output_window.see(tk.END)
        root.update_idletasks()

        with open(csv_file, mode='r',) as input_file:
            csv_reader = csv.reader(input_file, delimiter=';')
            for row in csv_reader:
                if line_count == 0:
                    line_count += 1
                    total_lines += 1
                    continue
                else:
                    date = row[4].split(':')
                    current_date = date[0]
                    if current_date not in histogram_table:
                        histogram_table[current_date] = int(row[3])
                    else:
                        histogram_table[current_date] += int(row[3])
                total_lines += 1
        line_count = 0
        file_count += 1

    for item in histogram_table:
        histogram_table[item] = (round(histogram_table[item]/(1024*1024),2))

    output_window.insert('end', 'Processed ' + str(total_lines) + ' lines' + '\n')
    output_window.see(tk.END)
    root.update_idletasks()

    output_window.insert('end', 'Writing file \'histogram.csv\'' + '\n')
    output_window.see(tk.END)
    root.update_idletasks()

    with open('histogram.csv', mode='w', newline='', encoding='utf-8') as output_file:
        csv_writer = csv.writer(output_file, delimiter=';')
        csv_writer.writerow(['Date', 'MiB'])
        for item in histogram_table:
            csv_writer.writerow([item,histogram_table[item]])
    
    return

## Tkinter setup ##

root = tk.Tk()
root.title('xToolbox')

# Window dimensions
window_width = 800
window_height = 600

#Screen dimensions
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()

# Center of screen
center_x = int(screen_width/2 - window_width/2)
center_y = int(screen_height/2 - window_height/2)

# Set root window dimensions and position
root.geometry(f'{window_width}x{window_height}+{center_x}+{center_y}')

# Divide window into columns (and rows)
root.columnconfigure(0, weight=1)
root.columnconfigure(1, weight=1)
root.columnconfigure(2, weight=1)
root.columnconfigure(3, weight=1)
root.columnconfigure(4, weight=1)

# Button to select directory.
select_directory = tk.Button(root, text = "Select Directory", command=browseButton)
select_directory.grid(row=1, column=2, sticky=tk.W)

# Label to store chosen directory.
folder_path = tk.StringVar()
directory_label = tk.Label(root, textvariable = folder_path, bg="#D3D3D3", width=70, padx=1, pady=5)
directory_label.grid(row=1, column=1, sticky=tk.W)

# Check buttons to select which operations to do.
rename_pcap_folders = tk.IntVar()
rename_pcap_button = tk.Checkbutton(root, text='Rename pcap folders',variable=rename_pcap_folders, onvalue=1, offvalue=0)
rename_pcap_button.grid(row=2, column=1, sticky=tk.W)

convert_pcap_files = tk.IntVar()
convert_button = tk.Checkbutton(root, text='Convert pcap to .csv files (Requires Tshark)',variable=convert_pcap_files, onvalue=1, offvalue=0)
convert_button.grid(row=3, column=1, sticky=tk.W)

parse_csv = tk.IntVar()
parse_csv_button = tk.Checkbutton(root, text='Parse csv files',variable=parse_csv, onvalue=1, offvalue=0)
parse_csv_button.grid(row=4, column=1, sticky=tk.W)

# Label for host IPv4 address
ipv4_label = tk.Label(root, text='Host IPv4 address:')
ipv4_label.grid(row=4, column=2)
# textbox for host IPv4 address
host_ipv4 = tk.StringVar()
ipv4_entry = tk.Entry(root)
ipv4_entry.grid(row=4, column=3)

# Label for host IPv6 address
ipv6_label = tk.Label(root, text='Host IPv6 address:')
ipv6_label.grid(row=5, column=2)
# textbox for host IPv6 address
host_ipv6 = tk.StringVar()
ipv6_entry = tk.Entry(root)
ipv6_entry.grid(row=5, column=3)

create_database = tk.IntVar()
create_database_button = tk.Checkbutton(root, text='Create IP Database (Requires ipinfo \'pip3 install ipinfo\')',variable=create_database, onvalue=1, offvalue=0)
create_database_button.grid(row=6, column=1, sticky=tk.W)

# Label for access token
access_token_label = tk.Label(root, text='IPinfo access token:')
access_token_label.grid(row=6, column=2)
# textbox for access token
access_token = tk.StringVar()
access_token_entry = tk.Entry(root, show='*')
access_token_entry.grid(row=6, column=3)

create_histogram = tk.IntVar()
create_histogram_button = tk.Checkbutton(root, text='Create histogram', variable=create_histogram, onvalue=1, offvalue=0)
create_histogram_button.grid(row=7, column=1, sticky=tk.W)

start_button = tk.Button(root, text='Go!', command=printOptions)
start_button.grid(row=1, column=3, sticky=tk.W)

output_window = tk.Text(root, height=25, pady=10)
output_window.grid(row=9, column=1, columnspan=3)

# Scrollbar on output_window
scrollbar = ttk.Scrollbar(root, orient='vertical', command=output_window.yview)
scrollbar.grid(row=9, column=4, sticky=tk.NS)


# Draw window
root.mainloop()