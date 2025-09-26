# OSAV - Open Source AntiVirus

OSAV (Open Source AntiVirus) is a lightweight, proof-of-concept antivirus application built in Python. It scans files for known virus signatures using MD5 , SHA1 and SHA256 hashes from ClamAV virus definition files (.cvd) or plain text (.txt) files. It features a dark-themed GUI, multi-threaded scanning, and basic file deletion capabilities for detected threats.

## Virus Database Import: 

Supports ClamAV .cvd files (e.g., main.cvd, daily.cvd) and .txt files containing MD5 hashes.

## Multi-threaded Scanning: 

Efficiently scans folders using multiple CPU cores while keeping one core free to maintain GUI responsiveness.

## Dark-themed GUI: 

Built with Tkinter, featuring a modern dark interface.

## Progress Tracking: 

Displays a progress bar and the currently scanned file path during operations.

## Threat Management: 

Allows deletion of detected suspicious files.

## External Links: 

Includes links to update virus definitions and support the project via donations.

<img src="https://github.com/sourcecode347/OSAV-Open_Source_AntiVirus/blob/main/screenshot.png" style="width:60%;height:auto;margin-left:20%;"/>

## Requirements

Python: Version 3.8 or higher.

Operating System: Tested on Windows 11 (should work on other platforms with Python support).

Tkinter (included with standard Python installation).



## Install dependencies on Linux:
        
        sudo apt install python3-tk
    
## Installation

Clone the repository:

    git clone https://github.com/sourcecode347/OSAV-Open_Source_AntiVirus.git
    cd OSAV-Open_Source_AntiVirus


Ensure Python 3.8+ is installed.

Run the application:
  
    python osav.py

## Usage

Launch OSAV: Run python osav.py to start the GUI.
Update Virus Database:
Click the "Update Virus Database" link (top-left) to visit ClamWin's virus definition page.
Download main.cvd or daily.cvd from ClamAV's database.
In OSAV, click "Import Database File (CVD/TXT)" and select a .cvd or .txt file containing MD5 hashes.
The progress bar shows import progress, and a confirmation displays the updated hash count.


## Scan a Folder:

Click "Scan Folder" and choose a directory to scan.
The progress bar and a label below it show the scanning progress and current file path.
Results appear in the listbox, showing detected files with their MD5 hashes.


## Manage Threats:

Select detected files in the listbox.
Click "Delete Selected" to remove them after confirming.


## Support the Project:

Click the "Donate" link (top-right) to contribute via Stripe.



## How It Works

Database: Stores MD5 hashes in a local virus_hashes.txt file. Duplicate hashes are automatically removed.
CVD Parsing: Extracts MD5 hashes from ClamAV .cvd files (.hdb and .mdb formats) after decompressing and unpacking.
Scanning: Computes MD5 hashes of files in the selected folder and compares them to the database. Uses multi-threading for performance.
GUI: Built with Tkinter, featuring a dark theme, progress bar, and real-time file path display.

## Limitations

Proof-of-Concept: Not a full-fledged antivirus; it relies on hash-based detection, which may miss polymorphic or new malware.
MD5 Only: Currently supports MD5 hashes (as used by ClamAV). Other hash types (e.g., SHA256) are not supported.
No Real-time Protection: Only manual folder scanning is available.
Basic Error Handling: May not handle all edge cases (e.g., corrupted .cvd files or permission issues).

## Contributing

Contributions are welcome! To contribute:

Fork the repository.

Create a feature branch (git checkout -b feature/YourFeature).
Commit changes (git commit -m 'Add YourFeature').
Push to the branch (git push origin feature/YourFeature).
Open a Pull Request.

Please ensure code follows PEP 8 and includes comments for clarity.
Future Improvements

Implement real-time scanning or scheduled scans.
Improve error handling for corrupted files or permissions.
Add a settings panel for custom configurations.
Integrate direct downloads from ClamAV's database.

## License

This project is licensed under the GPL 3.0 License. See the LICENSE file for details.

## Acknowledgments

Built with Python and Tkinter.
Uses ClamAV virus definitions from ClamAV and ClamWin.
Donation link powered by Stripe.

## Support

For issues or feature requests, open an issue on the GitHub repository.

## Disclaimer: 

This software is provided "as is" for educational purposes. Use at your own risk. For production antivirus needs, rely on established solutions.
