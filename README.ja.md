# AWS Observability Assessment Tool

[![License: MIT-0](https://img.shields.io/badge/License-MIT--0-blue.svg)](LICENSE)
![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)
![AWS CLI v2.37+](https://img.shields.io/badge/AWS%20CLI-v2.37%2B-orange.svg)
[![Python lint](https://github.com/aws-samples/sample-aws-observability-assessment/actions/workflows/python-lint.yml/badge.svg)](https://github.com/aws-samples/sample-aws-observability-assessment/actions/workflows/python-lint.yml)
[![cfn-lint](https://github.com/aws-samples/sample-aws-observability-assessment/actions/workflows/cfn-lint.yml/badge.svg)](https://github.com/aws-samples/sample-aws-observability-assessment/actions/workflows/cfn-lint.yml)

AWS 環境のオブザーバビリティ成熟度を、ログ、メトリクス、トレース、ダッシュボードとアラート、組織のプラクティスにわたる 52 の**ディスカバリーチェック**（AWS アカウントの設定に対して 1 項目毎に行うチェック）で評価します。
評価結果は、成熟度スコア、裏付けとなるエビデンス、推奨事項を含む HTML レポートとして出力されます。

[English](README.md) | 日本語

## サンプルレポート

実行前に、アセスメントが出力するレポートを確認できます。
どちらのサンプルも機密情報を含まないデータを使っており、ブラウザで開けます。

- **[シングルアカウントのアセスメントレポート][sample-report]：** 全体の成熟度スコア、カテゴリ別のチャート、推奨事項つきの優先対応領域、52 のディスカバリーチェックすべてについて各結果のエビデンスを含む検索可能なテーブル。
- **[組織サマリーレポート][sample-org-report]：** 組織スキャン全体のアカウントカバレッジ、スコアの範囲、カテゴリ別の平均、各アカウントのレポートへのリンク。

## 目次

- [クイックスタート](#クイックスタート)
  - [ローカルで実行する](#ローカルで実行する)
  - [CodeBuild でデプロイする](#codebuild-でデプロイする)
- [マルチアカウントアセスメント](#マルチアカウントアセスメント)
- [CLI オプション](#cli-オプション)
- [評価範囲と評価手法](#評価範囲と評価手法)
- [出力](#出力)
- [クリーンアップ](#クリーンアップ)
- [IAM 権限](#iam-権限)

## クイックスタート

### ローカルで実行する

ワークステーションからオンデマンドでアセスメントを実行したい場合は、このオプションを選択してください。

**前提条件：** Python 3.12 以降、設定済みの AWS 認証情報、[AWS CLI v2][aws-cli-install] バージョン 2.37.0 以降が必要です。
このツールは AWS CLI コマンドを実行します。
バージョン 2.37.0 には、バージョン 2.34.21 で追加された `devops-agent` コマンドと、バージョン 2.37.0 で追加された CloudWatch Omni の `cloudwatchomni` コマンドが含まれます。
それより古いバージョンの CLI では、CloudWatch Omni のチェック（51 と 52）は未評価として報告されます。

```bash
aws --version
pip install -r requirements.txt

python3 observability_assessment_comprehensive.py \
  --profile YOUR_PROFILE \
  --region us-west-2
```

### CodeBuild でデプロイする

AWS 環境に対して継続的にアセスメントを実行したい場合、CodeBuild が利用可能です。
リポジトリには 2 つの CloudFormation テンプレートが含まれます。

- `1-observability-assessment-role.yaml`：スキャン対象のアカウントにアセスメントロールを作成します。
- `2-observability-assessment-codebuild.yaml`：CodeBuild プロジェクト、レポートバケット、CodeBuild ロールを作成します。

シングルアカウントのアセスメントでは、テンプレート 2 だけをデプロイしてください。
デフォルト設定では同一アカウントにアセスメントロールを作成します。

```bash
aws cloudformation create-stack \
  --stack-name ObservabilityAssessmentCodeBuild \
  --template-body file://2-observability-assessment-codebuild.yaml \
  --parameters ParameterKey=AssessmentRegion,ParameterValue=us-west-2 \
               ParameterKey=CreateAssessmentRole,ParameterValue=yes \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-west-2
```

スタックはアセスメントロールの作成後、最初のビルドを開始します。
スタックの作成完了が意味するのは CodeBuild がビルドリクエストを受け付けたことであり、アセスメントが正常に終了したことではありません。
スタックの作成完了後、ビルドのステータスが `SUCCEEDED` になるのを待ち、想定された HTML と CSV のファイルがレポートバケット（スタック出力の `ReportBucketName`）にあることを確かめてください。

```bash
aws cloudformation wait stack-create-complete \
  --stack-name ObservabilityAssessmentCodeBuild --region us-west-2
BUILD_ID=$(aws codebuild list-builds-for-project \
  --project-name ObservabilityAssessmentCodeBuild \
  --query 'ids[0]' --output text --region us-west-2)
aws codebuild batch-get-builds --ids "$BUILD_ID" \
  --query 'builds[0].[buildStatus,logs.deepLink]' --output text \
  --region us-west-2
```

ステータスは最初 `IN_PROGRESS` のことがあります。
ビルドが完了するまで最後のコマンドを繰り返し実行してください。
アセスメントを再実行するには、以下のコマンドを使います。

```bash
aws codebuild start-build \
  --project-name ObservabilityAssessmentCodeBuild \
  --region us-west-2
```

CodeBuild プロジェクトは `NO_SOURCE` のインライン buildspec を使い、ビルドのたびに公開 Git リポジトリを `assessment-src` ディレクトリにシャロークローンします。
クローン元のリポジトリは `AssessmentRepoUrl` パラメータで指定します（デフォルトは `https://github.com/aws-samples/sample-aws-observability-assessment.git`）。
フォークやミラーなど、別の公開リポジトリのコードでアセスメントを実行したい場合は、その URL を指定してください。
シングルアカウントモードでもマルチアカウントモードでも、アセスメントはクローンしたコードから実行されます。
ビルド中に作業ディレクトリは変わらないため、レポートはこれまでどおり `assessment-result/` に出力され、HTML、CSV、ZIP アーカイブとして Amazon S3 にアップロードされます。
クローンしたコミットの SHA は CodeBuild のログに出力されます。
Python の依存パッケージは、クローンしたリポジトリの `requirements.txt` からインストールされます。

`AssessmentGitRef` では、`AssessmentRepoUrl` のどのブランチまたはタグを使うかを指定します（デフォルトは `main`）。
ソースコードを特定のコミットに固定したい場合は、`AssessmentGitRef` に公開済みのリリースタグを、`ExpectedAssessmentCommitSha` にそのタグが指すコミットの SHA（40 文字の完全な値）を指定します。
クローンしたコミットが `ExpectedAssessmentCommitSha` と一致しない場合、ビルドは失敗します。
`main` のようなブランチには、ビルドとビルドの間に新しいコミットが追加されることがあります。
そのため、ブランチを指定したまま `ExpectedAssessmentCommitSha` を設定すると、ブランチが更新された以降のビルドは失敗します。
これらのパラメータの変更は、スタックを更新して新たにビルドを開始することで反映されます。
CloudFormation テンプレートや IAM ポリシーが更新された場合は、アセスメントを再実行する前にデプロイ済みのスタックまたは StackSet を更新し、インフラストラクチャと権限をリポジトリの最新の内容に同期してください。

CodeBuild には、以下の宛先へのアウトバウンドの HTTPS 通信の許可が必要です。

- リポジトリのクローン：`AssessmentRepoUrl` のホスト（デフォルトは `github.com`）
- 依存パッケージのインストール：設定済みの Python パッケージインデックス
- AWS CLI の更新：`awscli.amazonaws.com`

このテンプレートには VPC 設定がありません。
CodeBuild を VPC に接続する場合は、CodeBuild の VPC 設定、サービスロールへの必要な EC2 権限の付与、上記のパブリックエンドポイントへの経路（通常は NAT 経由）もあわせて設定してください。
詳しくは [CodeBuild の VPC に関するドキュメント](https://docs.aws.amazon.com/codebuild/latest/userguide/vpc-support.html)を参照してください。
リポジトリのクローンや依存パッケージのインストールに失敗した場合、または指定した ref が存在しない場合は、アセスメントを実行する前にビルドが失敗します。
S3 に置いたソースへ切り替えて実行する仕組みはありません。

複数のアカウントにまたがるアセスメントについては、[マルチアカウントアセスメント](#マルチアカウントアセスメント)を参照してください。

## マルチアカウントアセスメント

マルチアカウントモードでは、中央のアセスメントアカウントで CodeBuild を実行し、各対象アカウントの `ObservabilityAssessmentRole` を引き受けて、組織サマリーとアカウントごとのレポートを生成します。
セットアップは次の 3 ステップです。

1. `1-observability-assessment-role.yaml` を各対象アカウントにデプロイします。
   個別のスタックとしても、サービスマネージド型の StackSet としてもデプロイできます。
2. アカウントを明示的に指定する（`AssessmentAccounts`）か、OU から検出する（`AssessmentOUs`）かを選びます。
3. `CreateAssessmentRole=no` を指定して、`2-observability-assessment-codebuild.yaml` を中央アカウントにデプロイします。

コマンド、推奨する委任管理者の構成、OU からの検出に必要な Organizations のリソースポリシーについては、[マルチアカウントアセスメントガイド](docs/MULTI_ACCOUNT.ja.md)を参照してください。

## CLI オプション

各オプションの用途は次のとおりです。

| オプション | 説明 |
| --- | --- |
| `--profile` | 認証に使う AWS プロファイル |
| `--region` | 評価する AWS リージョン（デフォルト：`us-west-2`） |
| `--role-arn` | チェックの実行前に引き受ける IAM ロールの ARN |
| `--single-check N` | ID を指定して 1 つのディスカバリーチェックを実行する |
| `--single-question N` | 設問（1–17）のチェックを実行してスコアを付ける |
| `--accounts` | マルチアカウントアセスメントの対象アカウント ID（カンマ区切り） |
| `--ou` | アカウント検出の起点とするルートまたは OU の ID（カンマ区切り） |
| `--cross-account-role` | `/service-role/` 配下の対象ロール名 |
| `--max-workers` | 並列に評価するアカウント数の上限（デフォルト：`5`） |
| `--debug` | 詳細な診断ログと失敗したコマンドのログを有効にする |

クロスアカウントロール名のデフォルトは `ObservabilityAssessmentRole` です。

## 評価範囲と評価手法

アセスメントは 52 のディスカバリーチェックを実行し、その結果を配点が等しい 17 の成熟度設問に対応づけます。

| カテゴリ | 設問 | 評価内容 |
| --- | --- | --- |
| ログ | Q1–Q4 | 収集、利用状況、アクセス、保持 |
| メトリクス | Q5–Q7 | 収集、利用状況、一元的なアクセス |
| トレース | Q8–Q9 | 計装、利用状況、相関付け |
| ダッシュボードとアラート | Q10–Q12 | アラーム、ダッシュボード、しきい値 |
| 組織 | Q13–Q17 | 戦略、SLO、ROI、AI/ML、RUM |


評価された各設問のスコアは 1–4 で、全体スコアは評価された設問の平均です。
全体スコアには Reactive、Proactive、Autonomous のいずれかのラベルが付きます。
評価できるエビデンスがない設問は **Not assessed** と表示され、平均から除外されます。
アセスメントは決定的なルールベースですが、一部のチェックはヒューリスティックや限られたサンプルを使います。
スコアをガバナンス上の判断に使う前に、[評価手法と制約](docs/ASSESSMENT_METHODOLOGY.ja.md)でスコアの区分、エビデンスの意味、既知の制約を確認してください。

## 出力

- **シングルアカウントの HTML：** `observability_assessment_<timestamp>_<account_id>.html`
- **シングルアカウントの CSV：** `discovery_checks_<timestamp>_<account_id>.csv`
- **マルチアカウントのサマリー：** `organization_summary_<timestamp>.html`
- **CodeBuild の ZIP アーカイブ：** `assessment-report_<UTC timestamp>.zip`
- **ローカルの出力ディレクトリ：** `assessment-result/`

CodeBuild はレポートと ZIP アーカイブを S3 のレポートバケットにアップロードします。
アセスメントの主な成果物は HTML レポートです。
新しいシングルアカウントレポートは Cloudscape のコンポーネントで構成され、エグゼクティブサマリー、ライト/ダークモードの切り替えを備えたレポートヘッダー、スコアとカバレッジの指標、カテゴリ別のチャート、推奨事項、ディスカバリーのテーブルを表示します。
ディスカバリーのテーブルは検索、並べ替え、ページ送りに対応し、チェックを選択すると右側にエビデンスのパネルが開きます。
組織サマリーは、アカウントカバレッジ、スコアの範囲、カテゴリ別の平均、検索可能なアカウントのテーブルを表示します。
どちらの HTML レポートも、末尾に設問のレベル、スコアの計算方法、全体の成熟度区分を説明する評価手法のセクションがあります。
カバレッジの表示では、利用できなかったチェック、評価されなかった設問、エビデンスが部分的な設問を、すべてのエビデンスで評価された結果と区別します。


各 HTML レポートはレポートデータとコンパイル済みの UI アセットを埋め込んでいるため、JavaScript を有効にしたブラウザで単一のファイルとして開けます。
レポートの生成にはリポジトリに同梱のコンパイル済みアセットを利用するため、ローカルでも CodeBuild でも、アセスメントの実行に Node.js は不要です。

CSV はディスカバリー結果の出力で、バージョン管理された安定的なデータ交換スキーマではありません。
チェック 12–50 の `Found Count` はリソースの総数ではなくバイナリ（1 または 0）です。
チェック 15 はクロスアカウントオブザーバビリティのリンクまたはシンクが存在するかを記録し、ほかのチェックは空でない結果が返ったかを記録します。
チェック 51–52（CloudWatch Omni）は、スペースとインテグレーションについて総数のうちアクティブな数を報告します。
`Status` 列では、各行が `Evaluated`、`Partial`、`Unavailable` のいずれかで示されます。
CSV を解釈するときは、HTML のエビデンスと評価手法のドキュメントを参照してください。

## クリーンアップ

レポートバケットは CodeBuild スタックを削除しても保持され、マルチアカウント構成では対象アカウントのロールと StackSet も残ります。
[クリーンアップガイド](docs/CLEANUP.ja.md)に従い、バケットを空にしてから、スタック、StackSet、Organizations のリソースポリシーを正しい順序で削除してください。

## IAM 権限

アセスメントは次のサービス群の API を使います。

- **オブザーバビリティ：** Amazon CloudWatch、CloudWatch Logs、AWS X-Ray、CloudWatch Application Signals、CloudWatch Synthetics、CloudWatch RUM、CloudWatch Observability Access Manager、CloudWatch Observability Admin
- **ワークロードとリソース：** Amazon EC2、AWS Lambda、Amazon ECS、Amazon EKS、AWS Systems Manager、Amazon Kinesis Data Streams、Amazon Data Firehose、Resource Groups Tagging API、AWS DevOps Agent
- **組織の検出：** AWS Organizations

ほぼすべてのアクションは読み取り専用（`Describe*`、`List*`、`Get*`）です。
完全なポリシーは `1-observability-assessment-role.yaml` を参照してください。

例外は EC2 の CloudWatch エージェントのチェックです。
このチェックは AWS マネージドの `AWS-RunShellScript` ドキュメントで `ssm:SendCommand` を使い、エージェントが実行中か、ログ収集が設定されているかを判定します。
インスタンスを意図的に変更することはなく、Systems Manager で管理されていないインスタンスではスキップされます。

全体のアセスメントでこのチェックだけを無効にする CLI オプションはありません。
環境で `ssm:SendCommand` が禁止されている場合は、チェックや設問を選んで実行するか、この権限を付与せずに EC2 エージェントのエビデンスを利用不可として扱ってください。

[aws-cli-install]: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html
[sample-report]: https://aws-samples.github.io/sample-aws-observability-assessment/sample-result/observability_assessment_single_account_sample.html
[sample-org-report]: https://aws-samples.github.io/sample-aws-observability-assessment/sample-result/org-scan-sample/organization_summary.html
