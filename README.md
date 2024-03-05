# FYP Repository
## windows-automated-hardening-tool
The Automated Windows OS Hardening Tool is a OS hardening tool with GUI to provide a more user-friendly and efficient way to secure your system. 

## Executing the Program 
1. download the file
2. run powershell_hardening-win_x64.exe
3. note: the executable should be executed with administrative privilege

## References
1. https://www.varonis.com/blog/windows-powershell-tutorials
2. https://github.com/ssh3ll/Windows-10-Hardening

## Screenshots
**Main Menu**
<br>
The main menu of the application consists of five buttons that will navigate the pages to each feature.
<br>
<p align="center">
 <img width="384" alt="image" src="https://github.com/Atyh078/windows-automated-hardening-tool/assets/127681205/b1bef459-8b2a-4e44-b1b3-36a840019b87">
</p>
<br><br><br>

**Remove Applications**
<br>
Selecting “Remove Applications” will direct users to the remove applications description page. Once user acknowledges what changes will be made by using this feature, users may choose to proceed with removing the applications or return to main menu.
<br>
<p align="center">
 <img width="374" alt="image" src="https://github.com/Atyh078/windows-automated-hardening-tool/assets/127681205/e962e613-574c-4506-997f-bc6a49f1f29a">
</p>
<br><br><br>

**Firewall Configurations**
<br>
Selecting “Firewall Configurations” will bring users into the description page for firewall configurations. The description explains the process and importance of firewall configurations to the users. Selecting “Start Scanning” will start running a scan on the user’s PC to check for missing inbound and outbound firewall rules.
<br>
<p align="center">
 <img width="403" alt="image" src="https://github.com/Atyh078/windows-automated-hardening-tool/assets/127681205/60351da9-d8c4-4358-b8d2-2a5f230dfb17">
</p>
<br><br>
The scan result will show all missing firewall rules. Selecting “Next” will allow users to proceed with the hardening process.
<br>
<p align="center">
 <img width="408" alt="image" src="https://github.com/Atyh078/windows-automated-hardening-tool/assets/127681205/d2ed0fb3-8f44-4515-ad55-822b181b71ae">
</p>
<br><br>
Users may select the firewall rules that they wish to apply to their PC by ticking the checkboxes or they may use the “Select All” button to apply all firewall rules. Selecting “Start Hardening” on the bottom will start the hardening process on the PC.
<br>
<p align="center">
 <img width="411" alt="image" src="https://github.com/Atyh078/windows-automated-hardening-tool/assets/127681205/32d5c0a7-004a-4c96-a1ec-a6114515f2e2">
</p>
<br><br><br>

**Windows Configurations**
<br>
Selecting “Windows Configurations” will bring users into the description page for Windows configurations. The description explains the process and importance of Windows configurations to the users. Selecting “Start Scanning” will start running a scan on the user’s PC to check for unnecessary Windows services that are running and Windows Auto-Update status.
<br>
<p align="center">
 <img width="395" alt="image" src="https://github.com/Atyh078/windows-automated-hardening-tool/assets/127681205/eac9e112-c877-4455-85e9-21a71f51d919">
</p>
<br><br>
The scan result will show all unnecessary Windows services that are running and Windows Auto-Update status. Selecting “Next” will allow users to proceed with the hardening process.
<br>
<p align="center">
 <img width="418" alt="image" src="https://github.com/Atyh078/windows-automated-hardening-tool/assets/127681205/2b9e7f9c-c91e-4730-91ed-3ef76081b43a">
</p>
<br><br>
Users may select the services that they wish to disable on their PC by ticking the checkboxes or they may use the “Select All” button to disable all unnecessary services. Selecting “Start Hardening” on the bottom will start the hardening process on the PC.
<br>
<p align="center">
 <img width="402" alt="image" src="https://github.com/Atyh078/windows-automated-hardening-tool/assets/127681205/06b96b0b-c2cb-4b4f-87e5-7e734e557f47">
</p>
<br><br><br>

**Microsoft Configurations**
<br>
Selecting “Microsoft Configurations” will bring users into the description page for Microsoft configurations. The description explains the process and importance of Microsoft configurations to the users. Selecting “Start Scanning” will start running a scan on the user’s PC to check for unnecessary Microsoft services that are running on the PC.
<br>
<p align="center">
 <img width="407" alt="image" src="https://github.com/Atyh078/windows-automated-hardening-tool/assets/127681205/bed83a78-19d8-4445-b2c9-128a963e4e48">
</p>
<br><br>
The scan result will show all unnecessary Microsoft services that are running. Selecting “Next” will allow users to proceed with the hardening process.
<br>
<p align="center">
 <img width="414" alt="image" src="https://github.com/Atyh078/windows-automated-hardening-tool/assets/127681205/904e7ed3-8f85-4abe-89e9-a5cf4b4b2e20">
</p>
<br><br>
Users may select the services that they wish to disable on their PC by ticking the checkboxes or they may use the “Select All” button to disable all unnecessary services. Selecting “Start Hardening” on the bottom will start the hardening process on the PC.
<br>
<p align="center">
 <img width="401" alt="image" src="https://github.com/Atyh078/windows-automated-hardening-tool/assets/127681205/943f25cc-4749-43bb-87ba-99132b3a5853">
</p>
<br><br><br>

**Password Management**
<br>
Selecting “Password Management” will direct users to the Password Management description page. The description explains the importance of saving user credentials into the Windows Credentials Manager and how this tool helps to ensure the security of user’s passwords. Selecting “Next” will bring users to the input page.
<br>
<p align="center">
 <img width="392" alt="image" src="https://github.com/Atyh078/windows-automated-hardening-tool/assets/127681205/03b5d456-f55b-4add-90a2-b9ae0fbc45a2">
</p>
<br><br>
In the input page, users will have to enter the website, server, or application link that corresponds to their credentials and decide if they wish to save their credentials into Windows Credentials Manager. Once user has filled up the form, selecting “Next” will allow the system to check if the password meets the complexity requirements. If it does, users’ credentials will be stored; if it does not, users will have to try again.
<br>
<p align="center">
 <img width="403" alt="image" src="https://github.com/Atyh078/windows-automated-hardening-tool/assets/127681205/392821f1-ab60-493f-b2b4-edd20e4958e9">
</p>
