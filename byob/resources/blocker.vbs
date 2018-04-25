On Error Resume Next
Set objWshShl = WScript.CreateObject("WScript.Shell")
Set objWMIService = GetObject("winmgmts:" & "{impersonationLevel=impersonate}!//./root/cimv2")
Set colMonitoredProcesses = objWMIService.ExecNotificationQuery("select * from __instancecreationevent " & " within 1 where TargetInstance isa 'Win32_Process'")
Do
	Set objLatestProcess = colMonitoredProcesses.NextEvent
	If objLatestProcess.TargetInstance.Name = "__PROCESS__" Then
		objLatestProcess.TargetInstance.Terminate
		End If
Loop