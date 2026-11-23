Set fso = CreateObject("Scripting.FileSystemObject")
Set ws = CreateObject("WScript.Shell")
baseDir = fso.GetParentFolderName(WScript.ScriptFullName)
ws.CurrentDirectory = baseDir

Function FindExecutable(exeName)
    Dim pathEnv, dirs, dir, candidate
    FindExecutable = ""
    pathEnv = ws.ExpandEnvironmentStrings("%PATH%")
    dirs = Split(pathEnv, ";")
    For Each dir In dirs
        dir = Trim(Replace(ws.ExpandEnvironmentStrings(dir), Chr(34), ""))
        If Len(dir) > 0 Then
            If Right(dir, 1) = "\" Then dir = Left(dir, Len(dir) - 1)
            If InStr(1, dir & "\", "\WindowsApps\", vbTextCompare) = 0 Then
                candidate = dir & "\" & exeName
                If fso.FileExists(candidate) Then
                    FindExecutable = candidate
                    Exit Function
                End If
            End If
        End If
    Next
End Function

Dim pyExe, runCmd
If fso.FileExists(baseDir & "\.venv\Scripts\pythonw.exe") Then
    runCmd = Chr(34) & baseDir & "\.venv\Scripts\pythonw.exe" & Chr(34) & " main.py"
ElseIf fso.FileExists(baseDir & "\venv\Scripts\pythonw.exe") Then
    runCmd = Chr(34) & baseDir & "\venv\Scripts\pythonw.exe" & Chr(34) & " main.py"
Else
    pyExe = FindExecutable("pythonw.exe")
    If Len(pyExe) > 0 Then
        runCmd = Chr(34) & pyExe & Chr(34) & " main.py"
    Else
        pyExe = FindExecutable("pyw.exe")
        If Len(pyExe) > 0 Then
            runCmd = Chr(34) & pyExe & Chr(34) & " -3 main.py"
        Else
            MsgBox "Python (pythonw.exe) was not found in .venv or system PATH.", 16, "XraySubMapper"
            WScript.Quit 1
        End If
    End If
End If

' Style 1 (SW_SHOWNORMAL): pythonw.exe has no console window, while style 0 would hide Qt6 top-level windows.
ws.Run runCmd, 1, False
