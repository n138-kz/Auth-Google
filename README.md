# Auth-Google

[![GitHub commit activity](https://img.shields.io/github/commit-activity/w/n138-kz/Auth-Google)](/../../commits)
[![GitHub commit activity](https://img.shields.io/github/commit-activity/t/n138-kz/Auth-Google)](/../../commits)
[![GitHub last commit](https://img.shields.io/github/last-commit/n138-kz/Auth-Google)](/../../commits)
[![GitHub repo license](https://img.shields.io/github/license/n138-kz/Auth-Google)](/../../LICENSE)
[![GitHub repo size](https://img.shields.io/github/repo-size/n138-kz/Auth-Google)](/../../)
[![GitHub repo file count](https://img.shields.io/github/directory-file-count/n138-kz/Auth-Google)](/../../)
[![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/n138-kz/Auth-Google)](/../../)
[![GitHub issues](https://img.shields.io/github/issues/n138-kz/Auth-Google)](/../../issues)
[![GitHub issues closed](https://img.shields.io/github/issues-closed/n138-kz/Auth-Google)](/../../issues)
[![GitHub pull requests closed](https://img.shields.io/github/issues-pr-closed/n138-kz/Auth-Google)](/../../pulls)
[![GitHub pull requests](https://img.shields.io/github/issues-pr/n138-kz/Auth-Google)](/../../pulls)
[![GitHub language count](https://img.shields.io/github/languages/count/n138-kz/Auth-Google)](/../../)
[![GitHub top language](https://img.shields.io/github/languages/top/n138-kz/Auth-Google)](/../../)

## Github actions page

[![https://n138-kz.github.io/Auth-Google/html/](https://img.shields.io/website?url=https%3A%2F%2Fauthz.n138.jp&up_message=in-operating&down_message=in-maintenance&cacheSeconds=3600)](https://n138-kz.github.io/Auth-Google/html/)

## Server status

[![authz.n138.jp](https://img.shields.io/website?url=https%3A%2F%2Fauthz.n138.jp&up_message=in-operating&down_message=in-maintenance&cacheSeconds=3600)](https://authz.n138.jp/)

## Descrption

This repos is test of google oauth api.

## Setup

```bash
cd /var/www/authn/
wget https://raw.githubusercontent.com/n138-kz/Auth-Google/main/google/composer.json
composer install
cd ./vendor/
git clone git@github.com:n138-kz/Auth-Google.git
mkdir /var/www/authn/google/
ln -s /var/www/authn/vendor/Auth-Google/google/index.php /var/www/authn/google/
ln -s /var/www/authn/vendor/Auth-Google/html/index.html /var/www/authn/
```

## API Console

- [Google Developer Console](https://console.cloud.google.com/apis/credentials?hl=ja&project=upbeat-splicer-325708)

## Refs

- [WEBページに「Googleアカウントでログイン」を実装する](https://qiita.com/kmtym1998/items/768212fe92dbaa384c27)
- [Google認証（ManagementAPI利用時）にて「idpiframe_initialization_failed 」エラー](https://qiita.com/kenken1981/items/9d738687c5cfb453be19)
- [クライアントサイド ウェブ アプリケーション用の OAuth 2.0](https://developers.google.com/identity/protocols/oauth2/javascript-implicit-flow?hl=ja#authorization-errors-origin-mismatch "Google Developers")
- [Google ログインからの移行](https://developers.google.com/identity/gsi/web/guides/migration?hl=ja#popup-mode_1 "Google Developers")

## Refs Repos

- [@googleapis/google-api-php-client](https://github.com/googleapis/google-api-php-client)

[![GitHub commit activity](https://img.shields.io/github/commit-activity/w/googleapis/google-api-php-client)](/../../commits)
[![GitHub commit activity](https://img.shields.io/github/commit-activity/t/googleapis/google-api-php-client)](/../../commits)
[![GitHub last commit](https://img.shields.io/github/last-commit/googleapis/google-api-php-client)](/../../commits)
[![GitHub repo license](https://img.shields.io/github/license/googleapis/google-api-php-client)](/../../LICENSE)
[![GitHub repo size](https://img.shields.io/github/repo-size/googleapis/google-api-php-client)](/../../)
[![GitHub repo file count](https://img.shields.io/github/directory-file-count/googleapis/google-api-php-client)](/../../)
[![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/googleapis/google-api-php-client)](/../../)
[![GitHub issues](https://img.shields.io/github/issues/googleapis/google-api-php-client)](/../../issues)
[![GitHub issues closed](https://img.shields.io/github/issues-closed/googleapis/google-api-php-client)](/../../issues)
[![GitHub pull requests closed](https://img.shields.io/github/issues-pr-closed/googleapis/google-api-php-client)](/../../pulls)
[![GitHub pull requests](https://img.shields.io/github/issues-pr/googleapis/google-api-php-client)](/../../pulls)
[![GitHub language count](https://img.shields.io/github/languages/count/googleapis/google-api-php-client)](/../../)
[![GitHub top language](https://img.shields.io/github/languages/top/googleapis/google-api-php-client)](/../../)
  
- [@n138-kz/Auth-via-Google-auth](https://github.com/n138-kz/Auth-via-Google-auth)

[![GitHub commit activity](https://img.shields.io/github/commit-activity/w/n138-kz/Auth-via-Google-auth)](/../../commits)
[![GitHub commit activity](https://img.shields.io/github/commit-activity/t/n138-kz/Auth-via-Google-auth)](/../../commits)
[![GitHub last commit](https://img.shields.io/github/last-commit/n138-kz/Auth-via-Google-auth)](/../../commits)
[![GitHub repo license](https://img.shields.io/github/license/n138-kz/Auth-via-Google-auth)](/../../LICENSE)
[![GitHub repo size](https://img.shields.io/github/repo-size/n138-kz/Auth-via-Google-auth)](/../../)
[![GitHub repo file count](https://img.shields.io/github/directory-file-count/n138-kz/Auth-via-Google-auth)](/../../)
[![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/n138-kz/Auth-via-Google-auth)](/../../)
[![GitHub issues](https://img.shields.io/github/issues/n138-kz/Auth-via-Google-auth)](/../../issues)
[![GitHub issues closed](https://img.shields.io/github/issues-closed/n138-kz/Auth-via-Google-auth)](/../../issues)
[![GitHub pull requests closed](https://img.shields.io/github/issues-pr-closed/n138-kz/Auth-via-Google-auth)](/../../pulls)
[![GitHub pull requests](https://img.shields.io/github/issues-pr/n138-kz/Auth-via-Google-auth)](/../../pulls)
[![GitHub language count](https://img.shields.io/github/languages/count/n138-kz/Auth-via-Google-auth)](/../../)
[![GitHub top language](https://img.shields.io/github/languages/top/n138-kz/Auth-via-Google-auth)](/../../)

- [@n138-kz/signIn](https://github.com/n138-kz/signIn "Basic signIn")

[![GitHub commit activity](https://img.shields.io/github/commit-activity/w/n138-kz/signIn)](/../../commits)
[![GitHub commit activity](https://img.shields.io/github/commit-activity/t/n138-kz/signIn)](/../../commits)
[![GitHub last commit](https://img.shields.io/github/last-commit/n138-kz/signIn)](/../../commits)
[![GitHub repo license](https://img.shields.io/github/license/n138-kz/signIn)](/../../LICENSE)
[![GitHub repo size](https://img.shields.io/github/repo-size/n138-kz/signIn)](/../../)
[![GitHub repo file count](https://img.shields.io/github/directory-file-count/n138-kz/signIn)](/../../)
[![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/n138-kz/signIn)](/../../)
[![GitHub issues](https://img.shields.io/github/issues/n138-kz/signIn)](/../../issues)
[![GitHub issues closed](https://img.shields.io/github/issues-closed/n138-kz/signIn)](/../../issues)
[![GitHub pull requests closed](https://img.shields.io/github/issues-pr-closed/n138-kz/signIn)](/../../pulls)
[![GitHub pull requests](https://img.shields.io/github/issues-pr/n138-kz/signIn)](/../../pulls)
[![GitHub language count](https://img.shields.io/github/languages/count/n138-kz/signIn)](/../../)
[![GitHub top language](https://img.shields.io/github/languages/top/n138-kz/signIn)](/../../)

- [@n138-kz/homepages](https://github.com/n138-kz/homepages.git)

[![GitHub commit activity](https://img.shields.io/github/commit-activity/w/n138-kz/homepages)](/../../commits)
[![GitHub commit activity](https://img.shields.io/github/commit-activity/t/n138-kz/homepages)](/../../commits)
[![GitHub last commit](https://img.shields.io/github/last-commit/n138-kz/homepages)](/../../commits)
[![GitHub repo license](https://img.shields.io/github/license/n138-kz/homepages)](/../../LICENSE)
[![GitHub repo size](https://img.shields.io/github/repo-size/n138-kz/homepages)](/../../)
[![GitHub repo file count](https://img.shields.io/github/directory-file-count/n138-kz/homepages)](/../../)
[![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/n138-kz/homepages)](/../../)
[![GitHub issues](https://img.shields.io/github/issues/n138-kz/homepages)](/../../issues)
[![GitHub issues closed](https://img.shields.io/github/issues-closed/n138-kz/homepages)](/../../issues)
[![GitHub pull requests closed](https://img.shields.io/github/issues-pr-closed/n138-kz/homepages)](/../../pulls)
[![GitHub pull requests](https://img.shields.io/github/issues-pr/n138-kz/homepages)](/../../pulls)
[![GitHub language count](https://img.shields.io/github/languages/count/n138-kz/homepages)](/../../)
[![GitHub top language](https://img.shields.io/github/languages/top/n138-kz/homepages)](/../../)

- [@n138-kz/mondai_3](https://github.com/n138-kz/mondai3)

[![GitHub commit activity](https://img.shields.io/github/commit-activity/w/n138-kz/mondai_3)](/../../commits)
[![GitHub commit activity](https://img.shields.io/github/commit-activity/t/n138-kz/mondai_3)](/../../commits)
[![GitHub last commit](https://img.shields.io/github/last-commit/n138-kz/mondai_3)](/../../commits)
[![GitHub repo license](https://img.shields.io/github/license/n138-kz/mondai_3)](/../../LICENSE)
[![GitHub repo size](https://img.shields.io/github/repo-size/n138-kz/mondai_3)](/../../)
[![GitHub repo file count](https://img.shields.io/github/directory-file-count/n138-kz/mondai_3)](/../../)
[![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/n138-kz/mondai_3)](/../../)
[![GitHub issues](https://img.shields.io/github/issues/n138-kz/mondai_3)](/../../issues)
[![GitHub issues closed](https://img.shields.io/github/issues-closed/n138-kz/mondai_3)](/../../issues)
[![GitHub pull requests closed](https://img.shields.io/github/issues-pr-closed/n138-kz/mondai_3)](/../../pulls)
[![GitHub pull requests](https://img.shields.io/github/issues-pr/n138-kz/mondai_3)](/../../pulls)
[![GitHub language count](https://img.shields.io/github/languages/count/n138-kz/mondai_3)](/../../)
[![GitHub top language](https://img.shields.io/github/languages/top/n138-kz/mondai_3)](/../../)

## License

[![License MIT](https://upload.wikimedia.org/wikipedia/commons/0/0c/MIT_logo.svg)](LICENSE)  
[MIT_License | wikipedia](https://ja.wikipedia.org/wiki/MIT_License)

Copyright (c) 2024 Yuu Komiya (n138)

[The MIT License](https://opensource.org/license/mit/)
> [n138-kz/*](./) is licensed under the `MIT License`.  
>
> Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
>
> `Copyright <YEAR> <COPYRIGHT HOLDER>`
>
> The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

[The MIT License](https://opensource.org/license/mit/)
> [n138-kz/*](./) は、MIT ライセンスに基づいてライセンスされています。  
> 以下に定める条件に従い、本ソフトウェアおよび関連文書のファイル（以下「ソフトウェア」）の複製を取得するすべての人に対し、ソフトウェアを無制限に扱うことを無償で許可します。これには、ソフトウェアの複製を使用、複写、変更、結合、掲載、頒布、サブライセンス、および/または販売する権利、およびソフトウェアを提供する相手に同じことを許可する権利も無制限に含まれます。  
>
> `Copyright (c) <著作権発生年> <著作権保持者名>`
>
> 上記の著作権表示および本許諾表示を、ソフトウェアのすべての複製または重要な部分に記載するものとします。
>
> ソフトウェアは「現状のまま」で、明示であるか暗黙であるかを問わず、何らの保証もなく提供されます。ここでいう保証とは、商品性、特定の目的への適合性、および権利非侵害についての保証も含みますが、それに限定されるものではありません。
> 作者または著作権者は、契約行為、不法行為、またはそれ以外であろうと、ソフトウェアに起因または関連し、あるいはソフトウェアの使用またはその他の扱いによって生じる一切の請求、損害、その他の義務について何らの責任も負わないものとします。

### Permissions / 許可

- Commercial use / 商用利用
- Modification / 改変
- Distribution / 再配布
- Private use / 私的使用

### Limitations / 制限事項

- Liability / 発生した問題に責任を負わない
- Warranty / 無保証
