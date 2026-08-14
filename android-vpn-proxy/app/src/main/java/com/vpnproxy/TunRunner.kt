package com.vpnproxy

import android.system.Os
import android.system.OsConstants
import java.util.concurrent.Executors

object TunRunner {

    init {
        System.loadLibrary("vpnrunner")
    }

    @Volatile
    private var pid = 0
    private val executor = Executors.newSingleThreadExecutor()

    private external fun start(tunFd: Int, argv: Array<String>, logPath: String): Int
    private external fun reap(childPid: Int): Int

    fun isRunning(): Boolean = pid > 0

    /**
     * Fork + exec tun2socks, passing the VpnService TUN fd to the child.
     * The child process runs with stdout/stderr redirected to [logPath].
     * [onExit] is invoked (on a background thread) when the child terminates.
     */
    fun launch(tunFd: Int, argv: Array<String>, logPath: String, onExit: (Int) -> Unit) {
        if (pid > 0) return
        val child = start(tunFd, argv, logPath)
        if (child <= 0) {
            onExit(-1)
            return
        }
        pid = child
        executor.execute {
            val code = reap(child)
            pid = 0
            onExit(code)
        }
    }

    fun stop() {
        val child = pid
        if (child > 0) {
            try {
                Os.kill(child, OsConstants.SIGTERM)
            } catch (_: Exception) {
            }
        }
    }
}
