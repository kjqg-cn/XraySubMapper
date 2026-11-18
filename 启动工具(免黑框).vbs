Set fso = CreateObject("Scripting.FileSystemObject")
Set ws = CreateObject("WScript.Shell")
baseDir = fso.GetParentFolderName(WScript.ScriptFullName)
ws.CurrentDirectory = baseDir

Function CommandExists(cmdName)
    On Error Resume Next
    rc = ws.Run("cmd /c where " & cmdName, 0, True)
    CommandExists = (Err.Number = 0 And rc = 0)
    On Error GoTo 0
End Function

Dim runCmd
If fso.FileExists(baseDir & "\.venv\Scripts\pythonw.exe") Then
    runCmd = Chr(34) & baseDir & "\.venv\Scripts\pythonw.exe" & Chr(34) & " main.py"
ElseIf fso.FileExists(baseDir & "\venv\Scripts\pythonw.exe") Then
    runCmd = Chr(34) & baseDir & "\venv\Scripts\pythonw.exe" & Chr(34) & " main.py"
ElseIf CommandExists("pythonw.exe") Then
    runCmd = "pythonw.exe main.py"
ElseIf CommandExists("pyw.exe") Then
    runCmd = "pyw.exe -3 main.py"
Else
    MsgBox "Python (pythonw.exe) was not found in .venv or system PATH.", 16, "XraySubMapper"
    WScript.Quit 1
End If

' Style 1 (SW_SHOWNORMAL): pythonw.exe has no console window, while style 0 would hide Qt6 top-level windows.
ws.Run runCmd, 1, False
