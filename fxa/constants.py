# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
ENVIRONMENT_URLS = {
    "production": {
        "authentication": "https://api.accounts.firefox.com/v1",
        "oauth": "https://oauth.accounts.firefox.com/v1",
        "content": "https://accounts.firefox.com/",
        "profile": "https://profile.accounts.firefox.com/v1",
        "token": "https://token.services.mozilla.com/",
    },
    "stage": {
        "authentication": "https://api-accounts.stage.mozaws.net/v1",
        "oauth": "https://oauth.stage.mozaws.net/v1",
        "content": "https://accounts.stage.mozaws.net/",
        "profile": "https://profile.stage.mozaws.net/v1",
        "token": "https://token.stage.mozaws.net/",
    },
    "stable": {
        "authentication": "https://stable.dev.lcip.org/auth/v1",
        "oauth": "https://oauth-stable.dev.lcip.org/v1",
        "content": "https://stable.dev.lcip.org/",
        "profile": "https://stable.dev.lcip.org/profile/v1",
        "token": None,
    }
}

PRODUCTION_URLS = ENVIRONMENT_URLS['production']
STAGE_URLS = ENVIRONMENT_URLS['stage']
STABLE_URLS = ENVIRONMENT_URLS['stable']
