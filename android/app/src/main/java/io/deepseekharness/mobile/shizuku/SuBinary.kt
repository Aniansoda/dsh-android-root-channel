package io.deepseekharness.mobile.shizuku

import java.io.File
import java.util.Locale

/**
 * `su` 可执行文件的定位与实现家族识别。
 *
 * 之前的实现假定「能跑 root 的一定是 KernelSU」，于是 `su -v` 里出现 `MAGISKSU` 就被判成
 * `ROOT_IMPL_NOT_KERNELSU`、整条根通道不可用。而 AI 的设备 Shell 只关心一件事：
 * **`su -c` 能不能拿到 UID 0**。谁提供的 `su` 是诊断信息，不是门槛。
 *
 * 定位策略（顺序固定，先命中先用）：
 *  1. `su` —— 交给 `execvp` 按 PATH 解析。KernelSU / Magisk / APatch 都会把 `su`
 *     挂进 `/system/bin`，这是正常路径；
 *  2. 显式候选路径 —— 部分 ROM 的 app 进程 PATH 不含 `/debug_ramdisk`、`/sbin`，
 *     或被 SELinux 收窄后 `execvp` 找不到，此时按已知安装位置逐个试。
 *
 * 本对象只做「找文件 + 起进程」，不含任何命令审查逻辑。
 */
object SuBinary {

    const val IMPL_KERNELSU = "kernelsu"
    const val IMPL_MAGISK = "magisk"
    const val IMPL_APATCH = "apatch"
    const val IMPL_SUPERSU = "supersu"
    const val IMPL_OTHER = "other"
    const val IMPL_UNKNOWN = "unknown"

    /** 已知的 `su` 安装位置；`execvp` 走不通时按这个顺序兜底。 */
    val CANDIDATE_PATHS = listOf(
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/debug_ramdisk/su",
        "/data/adb/ksu/bin/su",
        "/data/adb/apd/su",
        "/data/adb/magisk/su",
    )

    /**
     * `su -v` 输出里的实现特征。
     *
     * 顺序有意义：Magisk 自报 `MAGISKSU`，字面里含 `ksu`，所以 Magisk / APatch / SuperSU
     * 必须先判，KernelSU 家族最后判，否则 `MAGISKSU` 会被误认成 KernelSU 变体。
     */
    private val IMPLEMENTATION_MARKERS = listOf(
        IMPL_MAGISK to listOf("magisk"),
        // APatch 自报 `APatch`（部分版本带 `apd`）。
        IMPL_APATCH to listOf("apatch"),
        IMPL_SUPERSU to listOf("supersu", "superuser", "chainsdd"),
        IMPL_KERNELSU to listOf("kernelsu", "sukisu", "kowsu", "mksu"),
    )

    /**
     * 从 `su -v` 输出判定实现家族。
     *
     * 拿到输出但一个特征都不匹配时回 [IMPL_OTHER]（确实有 su，只是不认识）；
     * 完全没拿到输出时回 [IMPL_UNKNOWN]（可能只是探针超时）。
     */
    fun classify(versionOutput: String?): String {
        val text = versionOutput?.trim().orEmpty()
        if (text.isEmpty()) return IMPL_UNKNOWN
        val lowered = text.lowercase(Locale.ROOT)
        IMPLEMENTATION_MARKERS.forEach { (name, markers) ->
            if (markers.any { lowered.contains(it) }) return name
        }
        return IMPL_OTHER
    }

    /** 实现家族是否属于 KernelSU 一家（只用于诊断文案，不影响可用性判定）。 */
    fun isKernelSu(implementation: String?): Boolean = implementation == IMPL_KERNELSU

    /** 给人看的实现名；未知时回空串，界面据此决定是否显示这一行。 */
    fun displayName(implementation: String?): String = when (implementation) {
        IMPL_KERNELSU -> "KernelSU"
        IMPL_MAGISK -> "Magisk"
        IMPL_APATCH -> "APatch"
        IMPL_SUPERSU -> "SuperSU"
        IMPL_OTHER -> "其他 root 实现"
        else -> ""
    }

    /**
     * 可尝试的 `su` 启动方式，按优先级排列。
     *
     * 第一项恒为 `su`（PATH 解析）；其余是**完整的已知位置清单**，不预先按 `canExecute()` 过滤。
     * 不预检有两个原因：Android 上 `/data/adb` 下各路径的可见性受 SELinux 与命名空间影响，
     * `File.canExecute()` 报 false 而 execve 仍能成功；预检还会让「清单里有、但这台设备没有」
     * 的候选被静默跳过，诊断时看不出试过哪些。execve 失败代价只是一次快速返回。
     */
    fun candidates(): List<String> = buildList {
        add(FIRST_CANDIDATE)
        CANDIDATE_PATHS.forEach { path -> if (path !in this) add(path) }
    }

    /** 除 PATH 之外，是否有已知位置的 `su` 文件（只用于探测「装没装」，不影响启动尝试）。 */
    fun hasInstalledBinary(): Boolean = CANDIDATE_PATHS.any { runsAt(it) }

    /**
     * 按 [candidates] 顺序启动 `su`：第一个能起来的就用。
     *
     * 全部起不来时回 `null`（调用方据此报 `ROOT_SU_UNAVAILABLE`），不在这里抛异常，
     * 也不把「找不到 su」和「su 拒绝了这次请求」混成一件事。
     */
    fun start(arguments: List<String>, launcher: (List<String>) -> Process): Process? {
        candidates().forEach { binary ->
            val started = try {
                launcher(listOf(binary) + arguments)
            } catch (_: Exception) {
                // 这个位置不可用（ENOENT / EACCES / SELinux 拒绝），试下一个。
                null
            }
            if (started != null) return started
        }
        return null
    }

    /** 测试与诊断用：这个绝对路径现在能不能被执行。 */
    fun runsAt(path: String): Boolean = try {
        val file = File(path)
        file.exists() && file.canExecute()
    } catch (_: Exception) {
        false
    }

    private const val FIRST_CANDIDATE = "su"
}
