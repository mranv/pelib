use std::fmt::Write;
use std::io::Read;
use winapi::um::memoryapi::{VirtualAlloc, VirtualFree, WriteProcessMemory};
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::{ctypes::c_void, um::memoryapi::ReadProcessMemory};

use std::alloc::{alloc, Layout};


pub fn FillStructureFromArray<T, U>(base: &mut T, arr: &[U]) -> usize {
    unsafe {
        println!("{}",std::mem::size_of::<T>());
         println!("{}",std::mem::size_of_val(arr));
        if std::mem::size_of::<T>() != std::mem::size_of_val(arr) {
            println!("{}", std::mem::size_of::<T>());
            println!("{}", std::mem::size_of_val(arr));
            panic!("sizes are not equal to copy");
        }

        let mut handle = GetCurrentProcess();
        let mut byteswritten = 0;
        let res = WriteProcessMemory(
            handle,
            base as *mut _ as *mut c_void,
            arr as *const _ as *const c_void,
            std::mem::size_of::<T>(),
            &mut byteswritten,
        );

        return byteswritten;
    }
}

pub fn FillStructureFromMemory<T>(dest: &mut T,src: *const c_void,prochandle: *mut c_void,) -> usize {
    unsafe {
        let bytestoread: usize = std::mem::size_of::<T>();
        println!("size of structure is {}",bytestoread);
        let mut buffer: Vec<u8> = vec![0; bytestoread];
        let mut byteswritten = 0;

        let res = ReadProcessMemory(
            prochandle,
            src,
            buffer.as_mut_ptr() as *mut c_void,
            bytestoread,
            &mut byteswritten,
        );
        println!("array being filled: {:x?}",&buffer);
        FillStructureFromArray(dest, &buffer);

        return byteswritten;
    }
}


pub fn GetHeadersSize(buffer:&Vec<u8>) -> usize{
    if buffer.len()<2{ panic!("file size is less than 2")}
    let magic =&buffer[0..2];
    let magicstring =String::from_utf8_lossy(magic);
    if magicstring=="MZ"{
        if buffer.len()<64{ panic!("file size is less than 64")}
        let mut ntoffset =&buffer[60..64];
        unsafe{
        let offset = std::ptr::read(ntoffset.as_ptr() as *const i32) as usize;
        
        
        let bitversion =&buffer[offset+4+20..offset+4+20+2];
        let bit =std::ptr::read(bitversion.as_ptr() as *const u16);
        if bit==523{
            let index = offset + 24+60;
        let  headerssize =&buffer[index as usize..index as usize+4];
        let size = std::ptr::read(headerssize.as_ptr() as *const i32);
        println!("size of headers: {:x?}",size);   
        return size as usize;

        }
        else if bit==267{
        let index = offset + 24+60;
        let  headerssize =&buffer[index as usize..index as usize+4];
        let size = std::ptr::read(headerssize.as_ptr() as *const i32);
        println!("size of headers: {:x?}",size);   
        return size as usize;
        }
        else{
            panic!("invalid bit version");
        }
    }
        
    }
    else{
        panic!("its not a pe file");
    }
}


pub fn GetImageSize(buffer:&Vec<u8>) -> usize{
    if buffer.len()<2{ panic!("file size is less than 2")}
    let magic =&buffer[0..2];
    let magicstring =String::from_utf8_lossy(magic);
    if magicstring=="MZ"{
        if buffer.len()<64{ panic!("file size is less than 64")}
        let mut ntoffset =&buffer[60..64];
        unsafe{
        let offset = std::ptr::read(ntoffset.as_ptr() as *const i32) as usize;
        
        
        let bitversion =&buffer[offset+4+20..offset+4+20+2];
        let bit =std::ptr::read(bitversion.as_ptr() as *const u16);
        if bit==523{
            let index = offset + 24+60-4;
        let  headerssize =&buffer[index as usize..index as usize+4];
        let size = std::ptr::read(headerssize.as_ptr() as *const i32);
        println!("size of image: {:x?}",size);   
        return size as usize;

        }
        else if bit==267{
        let index = offset + 24+60-4;
        let  headerssize =&buffer[index as usize..index as usize+4];
        let size = std::ptr::read(headerssize.as_ptr() as *const i32);
        println!("size of image: {:x?}",size);   
        return size as usize;
        }
        else{
            panic!("invalid bit version");
        }
    }
        
    }
    else{
        panic!("its not a pe file");
    }
}


fn main() {

    use std::fs::File;
    let filepath = r#"D:\red teaming tools\calc2.exe"#;
    let mut buffer = Vec::new();

    let mut fd = File::open(filepath).unwrap();
    fd.read_to_end(&mut buffer);


    GetHeadersSize(&buffer);
    GetImageSize(&buffer);
    //println!("{:#?}", String::from_utf8_lossy(&buffer[0..2]));

    unsafe {
        let baseptr = VirtualAlloc(std::ptr::null_mut(), buffer.len(), 0x00001000, 0x40);

        std::ptr::copy(buffer.as_ptr(), baseptr as *mut u8, buffer.len());

        let mut dosheader = IMAGE_DOS_HEADER::default();
        FillStructureFromMemory(
            &mut dosheader,
            baseptr as *const c_void,
            GetCurrentProcess(),
        );
        println!("magic bytes: {:x?}", dosheader.e_magic);

        println!("baseptr: {:x?}",baseptr);
        println!("baseptr + elfanew: {:x?}",(baseptr as isize)+dosheader.e_lfanew as isize);
        let mut ntheader = IMAGE_NT_HEADERS64::default();
        FillStructureFromMemory(&mut ntheader, ((baseptr as isize)+dosheader.e_lfanew as isize) as *const c_void, GetCurrentProcess());
        println!("signature: {:x?}",ntheader.Signature);

        println!("sections count: {}",ntheader.FileHeader.NumberOfSections);
        
        println!("export directory: {:x?}",ntheader.OptionalHeader.ExportTable);
        
        println!("import directory: {:x?}",ntheader.OptionalHeader.ImportTable);

       
        let mut section:Vec<IMAGE_SECTION_HEADER> = vec![IMAGE_SECTION_HEADER::default();ntheader.FileHeader.NumberOfSections as usize];

        

       for i in 0..section.len(){
            FillStructureFromMemory(&mut section[i]  , 
            ((baseptr as isize)+dosheader.e_lfanew as isize+
                std::mem::size_of_val(&ntheader) as isize + (i as isize * std::mem::size_of::<IMAGE_SECTION_HEADER>() as isize)) as *const c_void,
                 GetCurrentProcess());
        }
        println!("{:#?}",section[1].getsecname());


        /*if ntheader.OptionalHeader.ImportTable.Size!=0{
           //let firstimportptr = baseptr as isize + ntheader.OptionalHeader.ImportTable.VirtualAddress as isize;
           // println!("{:x?}",firstimportptr);
            let mut import = IMAGE_IMPORT_DESCRIPTOR::default();
            FillStructureFromMemory(&mut import,
                 ((baseptr as isize)+(ntheader.OptionalHeader.ImportTable.VirtualAddress as isize)) as *const c_void,
                  GetCurrentProcess());
            println!("{:x?}",import);
        }*/


        let freeres = VirtualFree(baseptr, 0, 0x00008000);
    }
}



#[derive(Clone,Default,Debug)]
#[repr(C)]
pub  struct IMAGE_SECTION_HEADER{
           Name:[u8;8],
            VirtualSize: u32,
           VirtualAddress: u32,
         SizeOfRawData: u32,
          PointerToRawData: u32,
          PointerToRelocations: u32,
          PointerToLinenumbers: u32,
           NumberOfRelocations: u16,
           NumberOfLinenumbers: u16,
          Characteristics: u32
        
    }

impl IMAGE_SECTION_HEADER{
    fn getsecname(&mut self)-> String {
         String::from_utf8_lossy(&self.Name).to_string()
    }
}


#[repr(C)]
pub union chars_or_originalfirstthunk {
    Characteristics: u32,
    OriginalFirstThunk: u32,
}

#[derive(Debug, Clone, Default)]
#[repr(C)]
pub struct IMAGE_IMPORT_DESCRIPTOR {
    Characteristics_or_OriginalFirstThunk: u32,

    TimeDateStamp: u32,

    ForwarderChain: u32,

    Name: u32,

    FirstThunk: u32,
}

#[repr(C)]
pub union IMAGE_THUNK_DATA32 {
    pub ForwarderString: u32,

    pub Function: u32,

    pub Ordinal: u32,

    pub AddressOfData: u32,
}

#[derive(Debug, Clone, Default)]
#[repr(C)]
pub struct IMAGE_EXPORT_DIRECTORY {
    pub Characteristics: u32,
    pub TimeDateStamp: u32,
    pub MajorVersion: u16,
    pub MinorVersion: u16,
    pub Name: u32,
    pub Base: u32,
    pub NumberOfFnctions: u32,
    pub NumberOfNames: u32,
    pub AddressOfFunctions: u32,    // RVA from base of image
    pub AddressOfNames: u32,        // RVA from base of image
    pub AddressOfNameOrdinals: u32, // RVA from base of image
}

#[derive(Debug, Default, Clone)]
#[repr(C)]
pub struct IMAGE_OPTIONAL_HEADER64 {
    Magic: u16,

    MajorLinkerVersion: u8,

    MinorLinkerVersion: u8,

    SizeOfCode: u32,

    SizeOfInitializedData: u32,

    SizeOfUninitializedData: u32,

    AddressOfEntryPoint: u32,

    BaseOfCode: u32,

    ImageBase: i64,

    SectionAlignment: u32,

    FileAlignment: u32,

    MajorOperatingSystemVersion: u16,

    MinorOperatingSystemVersion: u16,

    MajorImageVersion: u16,

    MinorImageVersion: u16,

    MajorSubsystemVersion: u16,

    MinorSubsystemVersion: u16,

    Win32VersionValue: u32,

    SizeOfImage: u32,

    SizeOfHeaders: u32,

    CheckSum: u32,

    Subsystem: u16,

    DllCharacteristics: u16,

    SizeOfStackReserve: u64,

    SizeOfStackCommit: u64,

    SizeOfHeapReserve: u64,

    SizeOfHeapCommit: u64,

    LoaderFlags: u32,

    NumberOfRvaAndSizes: u32,

    ExportTable: IMAGE_DATA_DIRECTORY,

    ImportTable: IMAGE_DATA_DIRECTORY,

    ResourceTable: IMAGE_DATA_DIRECTORY,

    ExceptionTable: IMAGE_DATA_DIRECTORY,

    CertificateTable: IMAGE_DATA_DIRECTORY,

    BaseRelocationTable: IMAGE_DATA_DIRECTORY,

    Debug: IMAGE_DATA_DIRECTORY,

    Architecture: IMAGE_DATA_DIRECTORY,

    GlobalPtr: IMAGE_DATA_DIRECTORY,

    TLSTable: IMAGE_DATA_DIRECTORY,
    LoadConfigTable: IMAGE_DATA_DIRECTORY,
    BoundImport: IMAGE_DATA_DIRECTORY,

    IAT: IMAGE_DATA_DIRECTORY,

    DelayImportDescriptor: IMAGE_DATA_DIRECTORY,
    CLRRuntimeHeader: IMAGE_DATA_DIRECTORY,

    Reserved: IMAGE_DATA_DIRECTORY,
}

#[derive(Debug, Default, Clone)]
#[repr(C)]
pub struct IMAGE_OPTIONAL_HEADER32 {
    Magic: u16,

    MajorLinkerVersion: u8,

    MinorLinkerVersion: u8,

    SizeOfCode: u32,

    SizeOfInitializedData: u32,

    SizeOfUninitializedData: u32,

    AddressOfEntryPoint: u32,

    BaseOfCode: u32,

    // PE32 contains this additional field
    BaseOfData: u32,

    ImageBase: u32,

    SectionAlignment: u32,

    FileAlignment: u32,

    MajorOperatingSystemVersion: u16,

    MinorOperatingSystemVersion: u16,

    MajorImageVersion: u16,

    MinorImageVersion: u16,

    MajorSubsystemVersion: u16,

    MinorSubsystemVersion: u16,

    Win32VersionValue: u32,

    SizeOfImage: u32,

    SizeOfHeaders: u32,

    CheckSum: u32,

    Subsystem: u32,

    DllCharacteristics: u16,

    SizeOfStackReserve: u32,

    SizeOfStackCommit: u32,

    SizeOfHeapReserve: u32,

    SizeOfHeapCommit: u32,

    LoaderFlags: u32,

    NumberOfRvaAndSizes: u32,

    ExportTable: IMAGE_DATA_DIRECTORY,

    ImportTable: IMAGE_DATA_DIRECTORY,

    ResourceTable: IMAGE_DATA_DIRECTORY,

    ExceptionTable: IMAGE_DATA_DIRECTORY,

    CertificateTable: IMAGE_DATA_DIRECTORY,

    BaseRelocationTable: IMAGE_DATA_DIRECTORY,

    Debug: IMAGE_DATA_DIRECTORY,

    Architecture: IMAGE_DATA_DIRECTORY,

    GlobalPtr: IMAGE_DATA_DIRECTORY,

    TLSTable: IMAGE_DATA_DIRECTORY,
    LoadConfigTable: IMAGE_DATA_DIRECTORY,
    BoundImport: IMAGE_DATA_DIRECTORY,

    IAT: IMAGE_DATA_DIRECTORY,

    DelayImportDescriptor: IMAGE_DATA_DIRECTORY,
    CLRRuntimeHeader: IMAGE_DATA_DIRECTORY,

    Reserved: IMAGE_DATA_DIRECTORY,
}

#[derive(Debug, Default, Clone)]
#[repr(C)]
pub struct IMAGE_FILE_HEADER {
    Machine: u16,
    NumberOfSections: u16,
    TimeDateStamp: u32,
    PointerToSymbolTable: u32,
    NumberOfSymbols: u32,
    SizeOfOptionalHeader: u16,
    Characteristics: u16,
}

#[derive(Debug, Default, Clone)]
#[repr(C)]
pub struct IMAGE_DATA_DIRECTORY {
    VirtualAddress: u32,
    Size: u32,
}

#[derive(Debug, Default, Clone)]
#[repr(C)]
pub struct IMAGE_NT_HEADERS32 {
    Signature: u32,

    FileHeader: IMAGE_FILE_HEADER,

    OptionalHeader: IMAGE_OPTIONAL_HEADER32,
}

#[derive(Debug, Default, Clone)]
#[repr(C)]
pub struct IMAGE_NT_HEADERS64 {
    Signature: u32,

    FileHeader: IMAGE_FILE_HEADER,

    OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

#[derive(Debug, Default, Clone)]
#[repr(C)]

pub struct IMAGE_DOS_HEADER {
    e_magic: [u8; 2],  // Magic number
    e_cblp: u16,       // Bytes on last page of file
    e_cp: u16,         // Pages in file
    e_crlc: u16,       // Relocations
    e_cparhdr: u16,    // Size of header in paragraphs
    e_minalloc: u16,   // Minimum extra paragraphs needed
    e_maxalloc: u16,   // Maximum extra paragraphs needed
    e_ss: u16,         // Initial (relative) SS value
    e_sp: u16,         // Initial SP value
    e_csum: u16,       // Checksum
    e_ip: u16,         // Initial IP value
    e_cs: u16,         // Initial (relative) CS value
    e_lfarlc: u16,     // File address of relocation table
    e_ovno: u16,       // Overlay number
    e_res1: [u16; 4],  // Reserved words
    e_oemid: u16,      // OEM identifier (for e_oeminfo)
    e_oeminfo: u16,    // OEM information, e_oemid specific
    e_res2: [u16; 10], // Reserved words
    e_lfanew: i32,     // File address of new exe header
}
