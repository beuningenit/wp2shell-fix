<?php
$lines = file($argv[1], FILE_IGNORE_NEW_LINES);
$children = ["detect_wp_core_checksums","detect_wp_plugin_checksums","detect_wp_theme_checksum_gap",
             "detect_wp_administrator_accounts","detect_wp_check_active_plugins",
             "detect_wp_database_persistence","detect_wp_scheduled_tasks",
             "detect_wp_auto_update_posture","detect_wp_object_cache_context"];
$problems = [];
foreach ($children as $child) {
    $start = null;
    foreach ($lines as $i => $line) {
        if (strpos($line, $child . "() {") === 0) { $start = $i; break; }
    }
    if ($start === null) { $problems[] = $child . ": niet gevonden"; continue; }
    $end = $start + 1;
    while ($end < count($lines) && $lines[$end] !== "}") { $end++; }
    for ($j = $start; $j < $end; $j++) {
        if (trim($lines[$j]) !== "return 0") { continue; }
        $marked = strpos($lines[$j - 1], "detect_wp_mark_check_complete") !== false;
        $window = implode("\n", array_slice($lines, max($start, $j - 16), min(16, $j - $start)));
        $reported = strpos($window, "record_finding") !== false;
        if ($reported && !$marked) { $problems[] = $child . " regel " . ($j + 1); }
    }
}
echo implode("; ", $problems);
