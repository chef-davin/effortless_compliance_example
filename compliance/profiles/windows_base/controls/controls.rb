# copyright: 2018, The Authors

control 'windows-ie-101' do
  impact 1.0
  title 'IE 64-bit tab'
  desc 'This policy setting determines whether Internet Explorer 11 uses 64-bit processes (for greater security) or 32-bit processes (for greater compatibility) when running in Enhanced Protected Mode on 64-bit versions of Windows.Important: Some ActiveX controls and toolbars may not be available when 64-bit processes are used. If you enable this policy setting, Internet Explorer 11 will use 64-bit tab processes when running in Enhanced Protected Mode on 64-bit versions of Windows. If you disable this policy setting, Internet Explorer 11 will use 32-bit tab processes when running in Enhanced Protected Mode on 64-bit versions of Windows. If you don\'t configure this policy setting, users can turn this feature on or off using Internet Explorer settings. This feature is turned off by default.'
  describe registry_key('HKLM\Software\Policies\Microsoft\Internet Explorer\Main') do
    it { should exist }
    its('Isolation64Bit') { should eq 1 }
  end
end

control 'windows-ie-102' do
  impact 1.0
  title 'Run antimalware programs against ActiveX controls'
  desc 'Active X controls can contain potentially malicious code and must only be allowed to be downloaded from trusted sites. Signed code is better than unsigned code in that it may be easier to determine its author, but it is still potentially harmful, especially when coming from an untrusted zone. This policy setting allows you to manage whether users may download signed ActiveX controls from a page in the zone. If you enable this policy, users can download signed controls without user intervention. If you select Prompt in the drop-down box, users are queried whether to download controls signed by untrusted publishers. Code signed by trusted publishers is silently downloaded. If you disable the policy setting, signed controls cannot be downloaded.'
  describe registry_key('HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3') do
    it { should exist }
    its('270C') { should eq 0 }
  end
end

control 'microsoft-online-accounts' do
  impact 1.0
  title 'Microsoft Online Accounts'
  desc 'Disabling Microsoft account logon sign-in option, eg. logging in without having to use local credentials and using microsoft online accounts'
  ref 'Block Microsoft Accounts', url: 'https://technet.microsoft.com/en-us/library/jj966262(v=ws.11).aspx'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowYourAccount') do
    it { should exist }
    its('value') { should eq 1 }
  end
end

control 'disable-windows-store' do
  impact 1.0
  title 'Disable Windows Store'
  desc 'Ensure Turn off Automatic Download and Install ofupdates is set to Disabled'
  tag cis: '18.9.61.1'
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark', url: 'https://benchmarks.cisecurity.org/tools2/windows/CIS_Microsoft_Windows_Server_2012_R2_Benchmark_v2.2.1.pdf'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore') do
    it { should exist }
    its('AutoDownload') { should eq 4 }
    its('DisableOSUpgrade') { should eq 1 }
  end
end
