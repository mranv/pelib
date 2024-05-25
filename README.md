# PE File Analyzer

This Rust project provides functionality to read and analyze Portable Executable (PE) files. It uses various WinAPI functions to access and manipulate memory, read process memory, and handle PE file structures.

## Features

- Read and fill PE structures from arrays and memory
- Retrieve and print headers size from a PE file
- Retrieve and print image size from a PE file
- Example usage with a main function to load and analyze a PE file

## Dependencies

- `winapi`: For Windows API bindings
- `std::fmt::Write` and `std::io::Read`: For standard I/O operations

## Usage

### Functions

#### `FillStructureFromArray<T, U>(base: &mut T, arr: &[U]) -> usize`
Copies data from an array into a structure if the sizes match.

#### `FillStructureFromMemory<T>(dest: &mut T, src: *const c_void, prochandle: *mut c_void) -> usize`
Fills a structure with data read from memory.

#### `GetHeadersSize(buffer: &Vec<u8>) -> usize`
Returns the size of the headers of a PE file.

#### `GetImageSize(buffer: &Vec<u8>) -> usize`
Returns the size of the image of a PE file.

### Example

```rust
fn main() {
    use std::fs::File;
    use std::io::Read;

    let filepath = r#"D:\red teaming tools\calc2.exe"#;
    let mut buffer = Vec::new();
    let mut fd = File::open(filepath).unwrap();
    fd.read_to_end(&mut buffer).unwrap();

    GetHeadersSize(&buffer);
    GetImageSize(&buffer);

    unsafe {
        let baseptr = VirtualAlloc(std::ptr::null_mut(), buffer.len(), 0x00001000, 0x40);

        std::ptr::copy(buffer.as_ptr(), baseptr as *mut u8, buffer.len());

        let mut dosheader = IMAGE_DOS_HEADER::default();
        FillStructureFromMemory(&mut dosheader, baseptr as *const c_void, GetCurrentProcess());
        println!("magic bytes: {:x?}", dosheader.e_magic);

        let mut ntheader = IMAGE_NT_HEADERS64::default();
        FillStructureFromMemory(&mut ntheader, (baseptr as isize + dosheader.e_lfanew as isize) as *const c_void, GetCurrentProcess());
        println!("signature: {:x?}", ntheader.Signature);
        println!("sections count: {}", ntheader.FileHeader.NumberOfSections);
        println!("export directory: {:x?}", ntheader.OptionalHeader.ExportTable);
        println!("import directory: {:x?}", ntheader.OptionalHeader.ImportTable);

        let mut section: Vec<IMAGE_SECTION_HEADER> = vec![IMAGE_SECTION_HEADER::default(); ntheader.FileHeader.NumberOfSections as usize];
        for i in 0..section.len() {
            FillStructureFromMemory(
                &mut section[i],
                (baseptr as isize + dosheader.e_lfanew as isize + std::mem::size_of_val(&ntheader) as isize + (i as isize * std::mem::size_of::<IMAGE_SECTION_HEADER>() as isize)) as *const c_void,
                GetCurrentProcess(),
            );
        }
        println!("{:#?}", section[1].getsecname());

        let freeres = VirtualFree(baseptr, 0, 0x00008000);
    }
}
```

### PE Structures

#### `IMAGE_SECTION_HEADER`
Represents a section header in the PE file.

#### `IMAGE_IMPORT_DESCRIPTOR`
Represents an import descriptor.

#### `IMAGE_EXPORT_DIRECTORY`
Represents an export directory.

#### `IMAGE_OPTIONAL_HEADER64` and `IMAGE_OPTIONAL_HEADER32`
Represent optional headers for 64-bit and 32-bit PE files.

#### `IMAGE_FILE_HEADER`
Represents the file header of the PE file.

#### `IMAGE_DATA_DIRECTORY`
Represents a data directory entry.

#### `IMAGE_NT_HEADERS32` and `IMAGE_NT_HEADERS64`
Represent the NT headers for 32-bit and 64-bit PE files.

#### `IMAGE_DOS_HEADER`
Represents the DOS header of the PE file.

## Notes

- Ensure the file path is correct when loading the PE file.
- Handle errors appropriately in a production environment.
- The example usage demonstrates loading and analyzing a PE file.

## License

This project is licensed under the MIT License. See the LICENSE file for more details.
