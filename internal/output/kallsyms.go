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

// LoadKallsyms 加载 /proc/kallsyms（这是 Linux 内核导出的所有函数及其地址的列表）
func LoadKallsyms() error {
	// 1. 打开内核符号表文件。注意：通常需要 root 权限才能读取到准确的地址
	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		return err
	}
	defer file.Close()

	// 准备一个切片，用来存储所有的内核符号
	symbols := []KernelSymbol{}

	// 2. 逐行扫描文件内容。因为这个文件很大（通常有几十万行），使用 Scanner 性能更好
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// 每一行的格式通常是：ffffffff81000000 T startup_64
		// [0] 是十六进制地址, [1] 是符号类型, [2] 是函数名
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue // 跳过格式不规范的行
		}

		// 3. 将十六进制格式的地址字符串（parts[0]）解析为 uint64 数字
		addr, err := strconv.ParseUint(parts[0], 16, 64)
		if err != nil {
			continue // 解析失败（比如有些行地址显示为 0），则忽略
		}

		// 4. 将地址和函数名组合成结构体，放入列表中
		symbols = append(symbols, KernelSymbol{
			Address: addr,
			Name:    parts[2],
		})
	}

	// 5. 核心逻辑：按内存地址从小到大进行排序
	// 为什么要排序？
	// 因为后面翻译地址时，我们给出的地址可能正好在两个函数中间（比如在函数体内部）
	// 只有排好序，我们才能使用“二分查找”快速找到最接近该地址的函数名
	sort.Slice(symbols, func(i, j int) bool {
		return symbols[i].Address < symbols[j].Address
	})

	// 6. 将处理好的符号表保存到包级别的全局变量中，供全程序使用
	globalSymbolTable = &SymbolTable{Symbols: symbols}
	return nil
}

// GetSymbolName 根据内存地址查找对应的内核函数名
func (st *SymbolTable) GetSymbolName(addr uint64) string {
	// 1. 安全检查：如果符号表还没加载（st 为 nil）或者列表是空的
	// 则直接返回地址的十六进制字符串格式（例如 "0xffffffff81001234"）
	if st == nil || len(st.Symbols) == 0 {
		return fmt.Sprintf("0x%x", addr)
	}

	// 2. 核心算法：二分查找 (Binary Search)
	// 因为 st.Symbols 已经按地址从小到大排过序了，所以可以用二分法极速查找
	// sort.Search 会返回“第一个使函数返回 true 的索引”
	idx := sort.Search(len(st.Symbols), func(i int) bool {
		// 查找第一个起始地址大于目标地址的符号
		return st.Symbols[i].Address > addr
	})

	// 3. 结果定位逻辑：
	// 如果 idx > 0，说明我们找到了第一个“超过”该地址的函数。
	// 那么，包含该地址的函数必然是这一个函数的前面那一个。
	//
	// 举例：
	// 函数 A: 100~200
	// 函数 B: 200~300
	// 目标地址: 250
	// sort.Search 会找到第一个地址 > 250 的位置，即函数 B 之后的下一个位置（或 B 本身，取决于实现）
	// 回退一步 idx-1，就能准确拿到函数 B 的名字。
	if idx > 0 {
		return st.Symbols[idx-1].Name
	}

	// 4. 兜底处理：如果地址太小，连第一个函数的起始地址都没到，则返回原始十六进制地址
	return fmt.Sprintf("0x%x", addr)
}

func ResolveSymbol(addr uint64) string {
	return globalSymbolTable.GetSymbolName(addr)
}
