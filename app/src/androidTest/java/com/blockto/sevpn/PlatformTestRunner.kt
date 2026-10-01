package com.blockto.sevpn

import android.app.Activity
import android.app.Instrumentation
import android.content.Context
import android.os.Bundle
import org.junit.runner.Description
import org.junit.runner.JUnitCore
import org.junit.runner.notification.Failure
import org.junit.runner.notification.RunListener

/** Platform instrumentation + JUnit4; no Espresso or external UI driver needed. */
class PlatformTestRunner : Instrumentation() {
    override fun onCreate(arguments: Bundle?) { super.onCreate(arguments); start() }
    override fun onStart() {
        appContext = targetContext
        var count = 0; var total = 0; val failed = mutableSetOf<Description>()
        val junit = JUnitCore()
        junit.addListener(object : RunListener() {
            override fun testRunStarted(description: Description) { total = description.testCount() }
            private fun status(d: Description) = Bundle().apply {
                putString("id", "InstrumentationTestRunner"); putString("class", d.className); putString("test", d.methodName)
                putInt("numtests", total); putInt("current", count)
            }
            override fun testStarted(description: Description) { count++; sendStatus(1, status(description)) }
            override fun testFailure(failure: Failure) {
                failed += failure.description
                sendStatus(-2, status(failure.description).apply { putString("stack", failure.trace) })
            }
            override fun testFinished(description: Description) { if (description !in failed) sendStatus(0, status(description)) }
        })
        val result = junit.run(KeystoreTest::class.java, SocketInitializationTest::class.java, ExampleInstrumentedTest::class.java)
        finish(Activity.RESULT_OK, Bundle().apply { putString("stream", if (result.wasSuccessful()) "\nOK (${result.runCount} tests)\n" else "\nFAILURES!!! Tests run: ${result.runCount}, Failures: ${result.failureCount}\n") })
    }
    companion object { lateinit var appContext: Context; private set }
}
