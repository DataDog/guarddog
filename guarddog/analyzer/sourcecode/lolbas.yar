rule lolbas {
    meta:
      description = "Identify when a package uses a binary or script bundled in the OS (Live Of The Land) to leverage their capabilities. See more at https://lolbas-project.github.io"
    strings:
      $winbin1 = "addinutil.exe" nocase	
      $winbin2 = "atbroker.exe" nocase	
      $winbin3 = "bitsadmin.exe" nocase	
      $winbin4 = "certoc.exe" nocase	
      $winbin5 = "cmstp.exe" nocase	
      $winbin6 = "customshellhost.exe" nocase	
      $winbin7 = "extexport.exe" nocase	
      $winbin8 = "fsutil.exe" nocase	
      $winbin9 = "gpscript.exe" nocase	
      $winbin10 = "iediagcmd.exe" nocase	
      $winbin11 = "ieexec.exe" nocase	
      $winbin12 = "installutil.exe" nocase	
      $winbin13 = "mavinject.exe" nocase	
      $winbin14 = "mmc.exe" nocase	
      $winbin15 = "msconfig.exe" nocase	
      $winbin16 = "msedge.exe" nocase	
      $winbin17 = "mshta.exe" nocase	
      $winbin18 = "msiexec.exe" nocase	
      $winbin19 = "odbcconf.exe" nocase	
      $winbin20 = "offlinescannershell.exe" nocase	
      $winbin21 = "pcwrun.exe" nocase	
      $winbin22 = "presentationhost.exe" nocase	
      $winbin23 = "provlaunch.exe" nocase	
      $winbin24 = "rasautou.exe nocase"
      $winbin25 = "register-cimprovider.exe" nocase	
      $winbin26 = "regsvcs.exe" nocase	
      $winbin27 = "regsvr32.exe" nocase	
      $winbin28 = "rundll32.exe" nocase	
      $winbin29 = "runexehelper.exe" nocase	
      $winbin30 = "runonce.exe" nocase	
      $winbin31 = "runscripthelper.exe" nocase	
      $winbin32 = "scriptrunner.exe" nocase	
      $winbin33 = "setres.exe" nocase	
      $winbin34 = "settingsynchost.exe" nocase	
      $winbin35 = "stordiag.exe" nocase	
      $winbin36 = "syncappvpublishingserver.exe" nocase	
      $winbin37 = "verclsid.exe" nocase	
      $winbin38 = "wab.exe" nocase 
      $winbin39 = "wmic.exe" nocase	
      $winbin40 = "workfolders.exe" nocase	
      $winbin41 = "wuauclt.exe" nocase	
      $winbin42 = "xwizard.exe" nocase	
      $winbin43 = "msedge_proxy.exe" nocase	
      $winbin44 = "msedgewebview2.exe" nocase	
      $winbin45 = "acccheckconsole.exe" nocase	
      $winbin46 = "agentexecutor.exe" nocase	
      $winbin47 = "appcert.exe" nocase	
      $winbin48 = "appvlp.exe" nocase	
      $winbin49 = "bginfo.exe" nocase	
      $winbin50 = "coregen.exe" nocase	
      $winbin51 = "defaultpack.exe" nocase 
      $winbin52 = "devinit.exe" nocase	
      $winbin53 = "dotnet.exe" nocase	
      $winbin54 = "msdeploy.exe" nocase	
      $winbin55 = "sqlps.exe" nocase	
      $winbin56 = "sqltoolsps.exe" nocase	
      $winbin57 = "squirrel.exe" nocase	
      $winbin58 = "teams.exe" nocase	
      $winbin59 = "update.exe" nocase	
      $winbin60 = "vsiisexelauncher.exe" nocase	
      $winbin61 = "vsls-agent.exe" nocase
      $winbin62 = "at.exe" nocase
      $winbin63 = "wscript.exe" nocase
      $winbin64 = "powershell.exe" nocase

      $linbin1 = /\b(bash|\/bin\/sh)\b -(i|c)/
      $linbin2 = /\|.*?\b(bash|\/bin\/sh)\b/
      $linbin3 = /\b(curl|wget)\b.*?\|/
      $linbin4 = "busybox" 

      $script1 = "winrm.vbs" nocase

    condition:
        any of them
}

