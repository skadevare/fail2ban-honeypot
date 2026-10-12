<?php
// Trap page: anyone requesting /admin/ gets banned for 24h.
// Point this at wherever ban_script.php lives (ideally outside the web root).
require '/var/www/includes/ban_script.php';
