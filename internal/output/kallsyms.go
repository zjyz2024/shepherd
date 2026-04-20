package output

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// KernelSymbol 代表一个内核符号
type KernelSymbol struct {
	Address uint64
	Name    string
}

// SymbolTable 存储所有内核符号
type SymbolTable struct {
	Symbols []KernelSymbol
}

var globalSymbolTable *SymbolTable

// LoadKallsyms 加载 /proc/kallsyms
func LoadKallsyms() error {
	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		return err
	}
	defer file.Close()

	symbols := []KernelSymbol{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}

		addr, err := strconv.ParseUint(parts[0], 16, 64)
		if err != nil {
			continue
		}

		symbols = append(symbols, KernelSymbol{
			Address: addr,
			Name:    parts[2],
		})
	}

	// 按地址排序以便后续二分查找
	sort.Slice(symbols, func(i, j int) bool {
		return symbols[i].Address < symbols[j].Address
	})

	globalSymbolTable = &SymbolTable{Symbols: symbols}
	return nil
}

// GetSymbolName 根据地址查找符号名
func (st *SymbolTable) GetSymbolName(addr uint64) string {
	if st == nil || len(st.Symbols) == 0 {
		return fmt.Sprintf("0x%x", addr)
	}

	// 二分查找
	idx := sort.Search(len(st.Symbols), func(i int) bool {
		return st.Symbols[i].Address > addr
	})

	if idx > 0 {
		return st.Symbols[idx-1].Name
	}

	return fmt.Sprintf("0x%x", addr)
}

func ResolveSymbol(addr uint64) string {
	return globalSymbolTable.GetSymbolName(addr)
}
