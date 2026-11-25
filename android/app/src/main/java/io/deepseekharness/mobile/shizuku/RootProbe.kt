package io.deepseekharness.mobile.shizuku

import java.io.File
import java.util.concurrent.TimeUnit
import java.util.regex.Pattern

/**
 * 根通道探测：**任意的 `su` 实现**都算，只要它愿意给本应用 UID 0。
 *
 * 与上一版（`KernelSuProbe`）的差异：
 * 1. 可用性只看事实——`su -c id -u` 是否回 `0`。KernelSU / Magisk / APatch / SuperSU / 自带 su，
 *    一律同等对待；「不是 KernelSU」不再等于「不能用」；
 * 2. 实现家族降级为**诊断字段** [ProbeResult.implementation]（见 [SuBinary.classify]），
 *    界面可以显示「已就绪（Magisk）」，但不拿它卡功能；
 * 3. `su` 定位交给 [SuBinary]：先走 PATH，再按已知安装位置兜底，避免 app 进程 PATH 不全时
 *    明明装了 Magisk 却报「未安装」；
 * 4. 内核版本只作诊断。GKI 是 KernelSU 的历史门槛，对 Magisk/APatch 没有意义。
 *
 * 【探测原则】普通应用不能读写 `/data/adb`（会触发 DAC/SELinux 拒绝并留 audit 告警），
 * 所以一切判定都靠真实进程探测：`su -v` 拿实现名，`su -c id -u` 拿授权结果。
 */
object RootProbe {

    const val STATUS_READY = "ready"
    const val STATUS_NEEDS_ACTION = "needs_action"
    const val STATUS_UNSUPPORTED = "unsupported"

    const val REASON_READY = "READY"
    /** 设备上没有任何可用的 `su`（没装 root，或管理器把 `su` 藏了）。 */
    const val REASON_NOT_INSTALLED = "ROOT_NOT_INSTALLED"
    /** 有 `su`，但这次调用没拿到 UID 0：用户在管理器里还没放行。 */
    const val REASON_PERMISSION_REQUIRED = "ROOT_PERMISSION_REQUIRED"
    /** 旧码，仅用于读老载荷/老界面；新探测不再产生。 */
    const val REASON_ROOT_IMPL_NOT_KERNELSU = "ROOT_IMPL_NOT_KERNELSU"
    /** 旧码，仅用于读老载荷；新探测用 [REASON_NOT_INSTALLED]。 */
    const val REASON_KERNEL_UNSUPPORTED = "KERNELSU_KERNEL_UNSUPPORTED"

    /** 管理器包名，只用于诊断「装的是哪一家」；缺失不影响可用性判定。 */
    val MANAGER_PACKAGES = listOf(
        "me.weishu.kernelsu",
        "com.rifsxd.ksunext",
        "me.tiann.kernelsu",
        "com.sukisu.ultra",
        "com.topjohnwu.magisk",
        "me.bmax.apatch",
        "eu.chainfire.supersu",
    )

    const val CACHE_TTL_MS = 60_000L

    private const val SU_VERSION_TIMEOUT_MS = 1_500L
    private const val SU_GRANT_TIMEOUT_MS = 3_000L
    private const val MAX_PROBE_OUTPUT = 4_096

    private val KERNEL_VERSION_PATTERN = Pattern.compile(
        """Linux\s+version\s+(\d+)\.(\d+)\.(\d+)""",
        Pattern.CASE_INSENSITIVE,
    )

    data class ProbeResult(
        val status: String,
        val reason: String,
        /** `kernelsu` / `magisk` / `apatch` / `supersu` / `other` / `unknown`。 */
        val implementation: String,
        val kernelVersion: String?,
        val isGkiSupported: Boolean,
        val isSuAvailable: Boolean,
        /** 本次探测里 `su -c id -u` 是否真的拿到 0。 */
        val isRootGranted: Boolean,
        /** `su -v` 的原始输出（已裁剪），用于诊断面板与问题上报。 */
        val suVersion: String? = null,
    ) {
        val isKernelSuDetected: Boolean get() = SuBinary.isKernelSu(implementation)

        /** 给人看的实现名，未知时为空串。 */
        val implementationName: String get() = SuBinary.displayName(implementation)

        /** 可用但有保留意见时的一句话说明，供界面提示；没有保留意见时为 null。 */
        fun warning(): String? = when {
            status == STATUS_READY && implementation == SuBinary.IMPL_KERNELSU && !isGkiSupported ->
                "内核不在 GKI 2.0（>= 5.10）区间，走的是 KernelSU 的 LKM 路线；若通道异常请优先怀疑内核模块版本"
            status == STATUS_READY && implementation == SuBinary.IMPL_UNKNOWN ->
                "已拿到 UID 0，但没读到 su 版本号；管理器可能未响应 su -v，不影响执行"
            else -> null
        }
    }

    /** 解析 `/proc/version`，取主次版本号。 */
    fun parseKernelVersion(procVersionText: String): Pair<Int, Int>? {
        val matcher = KERNEL_VERSION_PATTERN.matcher(procVersionText)
        if (!matcher.find()) return null
        val major = matcher.group(1)?.toIntOrNull() ?: return null
        val minor = matcher.group(2)?.toIntOrNull() ?: return null
        return major to minor
    }

    /** 内核主次版本号是否落进 GKI 2.0 区间（>= 5.10）；仅作 KernelSU 的诊断信息。 */
    fun isGkiCompatible(major: Int, minor: Int): Boolean = major > 5 || (major == 5 && minor >= 10)

    /**
     * 纯事实推导：可用性只看「有没有 su」与「su 给不给 UID 0」。
     *
     * @param implementation [SuBinary.classify] 的结果；`null` 表示没拿到 `su -v` 输出，
     *        此时按 [SuBinary.IMPL_UNKNOWN] 处理，不因此降级。
     */
    fun evaluate(
        isGkiSupported: Boolean,
        hasSuBinary: Boolean,
        isRootGranted: Boolean,
        rawVersion: String? = null,
        implementation: String? = null,
        suVersion: String? = null,
    ): ProbeResult {
        val impl = implementation?.takeIf { it.isNotEmpty() } ?: SuBinary.IMPL_UNKNOWN
        if (!hasSuBinary) {
            return ProbeResult(
                status = STATUS_UNSUPPORTED,
                reason = REASON_NOT_INSTALLED,
                implementation = impl,
                kernelVersion = rawVersion,
                isGkiSupported = isGkiSupported,
                isSuAvailable = false,
                isRootGranted = false,
            )
        }
        if (!isRootGranted) {
            return ProbeResult(
                status = STATUS_NEEDS_ACTION,
                reason = REASON_PERMISSION_REQUIRED,
                implementation = impl,
                kernelVersion = rawVersion,
                isGkiSupported = isGkiSupported,
                isSuAvailable = true,
                isRootGranted = false,
                suVersion = suVersion,
            )
        }
        return ProbeResult(
            status = STATUS_READY,
            reason = REASON_READY,
            implementation = impl,
            kernelVersion = rawVersion,
            isGkiSupported = isGkiSupported,
            isSuAvailable = true,
            isRootGranted = true,
            suVersion = suVersion,
        )
    }

    @Volatile
    private var cached: Pair<Long, ProbeResult>? = null

    /** 测试注入点：默认真的按 [SuBinary.candidates] 起进程。 */
    var processLauncher: (List<String>) -> Process = { argv ->
        ProcessBuilder(argv).redirectErrorStream(true).start()
    }

    /** 丢弃缓存；用户在管理器里改了授权之后应主动调用。 */
    fun clearCache() {
        cached = null
    }

    /**
     * 读取本机 `/proc/version` 并探测环境；结果带 [CACHE_TTL_MS] 缓存。
     *
     * @param packageChecker 交给宿主 `PackageManager` 判断管理器是否存在（只影响诊断字段）。
     */
    fun probeLocal(
        packageChecker: ((String) -> Boolean)? = null,
        nowMs: Long = System.currentTimeMillis(),
        force: Boolean = false,
    ): ProbeResult {
        if (!force) {
            cached?.let { (at, result) -> if (nowMs - at in 0 until CACHE_TTL_MS) return result }
        }
        return detect(packageChecker).also { cached = nowMs to it }
    }

    private fun detect(packageChecker: ((String) -> Boolean)?): ProbeResult {
        val procVersion = try {
            File("/proc/version").readText().trim()
        } catch (_: Exception) {
            ""
        }
        val versionPair = parseKernelVersion(procVersion)
        val isGki = versionPair?.let { isGkiCompatible(it.first, it.second) } ?: false

        val hasManager = packageChecker?.let { checker -> MANAGER_PACKAGES.any { checker(it) } } ?: false

        val versionRun = runSu(listOf("-v"), SU_VERSION_TIMEOUT_MS)
        val suVersion = versionRun?.output?.takeIf { it.isNotBlank() }
        val hasSuBinary = versionRun != null || SuBinary.hasInstalledBinary()
        val implementation = when {
            suVersion != null -> SuBinary.classify(suVersion)
            // 没有版本读数时，管理器包名是唯一的旁证；都没有就记 unknown。
            hasManager -> SuBinary.IMPL_OTHER
            else -> SuBinary.IMPL_UNKNOWN
        }

        // 只有 su 真能跑起来（不是超时等用户点弹窗）时才算授权成功。
        val isGranted = if (versionRun == null) {
            false
        } else {
            val grantRun = runSu(listOf("-c", "id -u"), SU_GRANT_TIMEOUT_MS)
            grantRun != null && !grantRun.timedOut && grantRun.exitCode == 0 &&
                grantRun.output.lineSequence().any { it.trim() == "0" }
        }

        return evaluate(
            isGkiSupported = isGki,
            hasSuBinary = hasSuBinary,
            isRootGranted = isGranted,
            rawVersion = versionPair?.let { "${it.first}.${it.second}" },
            implementation = implementation,
            suVersion = suVersion,
        )
    }

    private data class SuRun(val exitCode: Int, val output: String, val timedOut: Boolean)

    /**
     * 拉起一次 `su` 调用并读取输出。
     *
     * - 读流在独立线程里做：`waitFor` 之前就开始读，避免输出撑满管道把子进程卡死；
     * - 超时不代表失败：管理器正在弹窗等用户点授权也会超时，返回 [SuRun.timedOut] 交调用方判断；
     * - 返回 `null` 表示所有候选位置都拉不起 `su`（未安装或内核拒绝 `execve`）。
     */
    private fun runSu(arguments: List<String>, timeoutMs: Long): SuRun? {
        val process = SuBinary.start(arguments, processLauncher) ?: return null

        val buffer = StringBuilder()
        val reader = Thread {
            try {
                process.inputStream.bufferedReader().use { stream ->
                    val chunk = CharArray(512)
                    while (buffer.length < MAX_PROBE_OUTPUT) {
                        val read = stream.read(chunk)
                        if (read <= 0) break
                        buffer.appendRange(chunk, 0, minOf(read, MAX_PROBE_OUTPUT - buffer.length))
                    }
                }
            } catch (_: Exception) {
                // 读流失败只影响诊断文本，不影响判定。
            }
        }
        reader.isDaemon = true
        reader.start()

        val completed = try {
            process.waitFor(timeoutMs, TimeUnit.MILLISECONDS)
        } catch (_: Exception) {
            false
        }
        if (!completed) {
            process.destroyForcibly()
            return SuRun(exitCode = -1, output = "", timedOut = true)
        }
        reader.join(200)
        return SuRun(exitCode = process.exitValue(), output = buffer.toString().trim(), timedOut = false)
    }
}
