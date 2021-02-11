# Autoincrease Premium File Share Quota

## Overview
This method will create an Azure Function with a timer trigger that checks every 5 minutes to see whether the target premium file share has 20% or less of its quota still free. If so, this function will automatically increase the file share's quota by 20%.

## Options
1. Use the ARM template.
2. Do all of this manually using the step-by-step guide.
