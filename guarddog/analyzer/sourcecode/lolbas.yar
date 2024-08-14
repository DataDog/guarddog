rule lolbas {
    strings:
      $bin1 = "addinutil.exe" nocase	
      $bin2 = "atbroker.exe" nocase	
      $bin3 = "bitsadmin.exe" nocase	
      $bin4 = "certoc.exe" nocase	
      $bin5 = "cmstp.exe" nocase	
      $bin6 = "customshellhost.exe" nocase	
      $bin7 = "extexport.exe" nocase	
      $bin8 = "fsutil.exe" nocase	
      $bin9 = "gpscript.exe" nocase	
      $bin10 = "iediagcmd.exe" nocase	
      $bin11 = "ieexec.exe" nocase	
      $bin12 = "installutil.exe" nocase	
      $bin13 = "mavinject.exe" nocase	
      $bin14 = "mmc.exe" nocase	
      $bin15 = "msconfig.exe" nocase	
      $bin16 = "msedge.exe" nocase	
      $bin17 = "mshta.exe" nocase	
      $bin18 = "msiexec.exe" nocase	
      $bin19 = "odbcconf.exe" nocase	
      $bin20 = "offlinescannershell.exe" nocase	
      $bin21 = "pcwrun.exe" nocase	
      $bin22 = "presentationhost.exe" nocase	
      $bin23 = "provlaunch.exe" nocase	
      $bin24 = "rasautou.exe nocase"
      $bin25 = "register-cimprovider.exe" nocase	
      $bin26 = "regsvcs.exe" nocase	
      $bin27 = "regsvr32.exe" nocase	
      $bin28 = "rundll32.exe" nocase	
      $bin29 = "runexehelper.exe" nocase	
      $bin30 = "runonce.exe" nocase	
      $bin31 = "runscripthelper.exe" nocase	
      $bin32 = "scriptrunner.exe" nocase	
      $bin33 = "setres.exe" nocase	
      $bin34 = "settingsynchost.exe" nocase	
      $bin35 = "stordiag.exe" nocase	
      $bin36 = "syncappvpublishingserver.exe" nocase	
      $bin37 = "verclsid.exe" nocase	
      $bin38 = "wab.exe" nocase 
      $bin39 = "wmic.exe" nocase	
      $bin40 = "workfolders.exe" nocase	
      $bin41 = "wuauclt.exe" nocase	
      $bin42 = "xwizard.exe" nocase	
      $bin43 = "msedge_proxy.exe" nocase	
      $bin44 = "msedgewebview2.exe" nocase	
      $bin45 = "acccheckconsole.exe" nocase	
      $bin46 = "agentexecutor.exe" nocase	
      $bin47 = "appcert.exe" nocase	
      $bin48 = "appvlp.exe" nocase	
      $bin49 = "bginfo.exe" nocase	
      $bin50 = "coregen.exe" nocase	
      $bin51 = "defaultpack.exe" nocase 
      $bin52 = "devinit.exe" nocase	
      $bin53 = "dotnet.exe" nocase	
      $bin54 = "msdeploy.exe" nocase	
      $bin55 = "sqlps.exe" nocase	
      $bin56 = "sqltoolsps.exe" nocase	
      $bin57 = "squirrel.exe" nocase	
      $bin58 = "teams.exe" nocase	
      $bin59 = "update.exe" nocase	
      $bin60 = "vsiisexelauncher.exe" nocase	
      $bin61 = "vsls-agent.exe" nocase
      $bin62 = "at.exe" nocase
      $bin63 = "wscript.exe" nocase
      $bin64 = "powershell.exe" nocase

      $script1 = "winrm.vbs" nocase

    condition:
        any of them
}

