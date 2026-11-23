// NetDiag 单文件启动器
// 把 NetDiag.exe 及其火绒运行库/资源内嵌到一个 exe，运行时释放到临时目录执行。
// 功能逻辑与接口完全不变，仅解决"必须依赖火绒安装目录"的问题。
package main

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

//go:embed payload/*
var payload embed.FS

const (
	appExe   = "NetDiag.exe"
	dirPrefix = "NetDiagStandalone_"
)

func main() {
	// 临时目录：%TEMP%\NetDiagStandalone_<pid>_<nanos>
	base := os.TempDir()
	tag := fmt.Sprintf("%s%d_%d", dirPrefix, os.Getpid(), time.Now().UnixNano())
	dir := filepath.Join(base, tag)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fatal("创建临时目录失败: %v", err)
	}

	// 释放内嵌文件
	err := fs.WalkDir(payload, "payload", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel("payload", path)
		dst := filepath.Join(dir, rel)
		data, err := payload.ReadFile(path)
		if err != nil {
			return fmt.Errorf("读取内嵌资源 %s: %w", path, err)
		}
		if err := os.WriteFile(dst, data, 0o755); err != nil {
			return fmt.Errorf("写出 %s: %w", dst, err)
		}
		return nil
	})
	if err != nil {
		_ = os.RemoveAll(dir)
		fatal("释放资源失败: %v", err)
	}

	exe := filepath.Join(dir, appExe)

	// 构造命令：透传所有命令行参数
	args := os.Args[1:]
	cmd := exec.Command(exe, args...)
	cmd.Dir = dir

	// Windows: 不弹出控制台窗口（GUI 程序）
	if runtime.GOOS == "windows" {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			HideWindow:    true,
			CreationFlags: 0,
		}
	}

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// 启动
	if err := cmd.Start(); err != nil {
		if os.Getenv("NETDIAG_KEEP_TEMP") == "1" {
			fmt.Fprintf(os.Stderr, "[NetDiag] 保留临时目录: %s\n", dir)
		} else {
			_ = os.RemoveAll(dir)
		}
		fatal("启动 NetDiag.exe 失败: %v", err)
	}

	// 等待退出
	_ = cmd.Wait()

	// 给 DLL 卸载留一点时间，再清理临时目录
	time.Sleep(300 * time.Millisecond)
	if os.Getenv("NETDIAG_KEEP_TEMP") == "1" {
		fmt.Fprintf(os.Stderr, "[NetDiag] 保留临时目录: %s\n", dir)
	} else {
		_ = os.RemoveAll(dir)
	}
}

func fatal(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	fmt.Fprintln(os.Stderr, "[NetDiag] "+msg)
	// GUI 子系统下无控制台，不能等待 stdin（会永久阻塞）；仅打印错误后退出。
	os.Exit(1)
}
