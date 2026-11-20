# 評価手法と現時点の制約

[English](ASSESSMENT_METHODOLOGY.md) | 日本語

このドキュメントでは、現在の実装がエビデンスを収集し、成熟度レベルを割り当て、マルチアカウントの結果を集計する方法を説明します。
目的は、ツールが評価できる範囲を実際より広く見せずに、アセスメントの出力を解釈できるようにすることです。

## 評価モデル

このツールは 52 の**ディスカバリーチェック**（AWS アカウントの設定に対して 1 項目毎に行うチェック）を登録し、その結果を 17 の成熟度設問に対応づけます。

| カテゴリ | 設問 |
| --- | --- |
| ログ | Q1–Q4 |
| メトリクス | Q5–Q7 |
| トレース | Q8–Q9 |
| ダッシュボードとアラート | Q10–Q12 |
| 組織 | Q13–Q17 |

評価できるエビデンスがある設問には、1 から 4 までの整数のレベルが割り当てられます。
エビデンスとなるチェックがすべて失敗した設問は **Not assessed** になります。
全体スコアは評価された設問のレベルの単純平均で、カテゴリのスコアはそのカテゴリ内で評価された設問の平均です。
評価された設問が 1 つもない場合、レポートには成熟度スコアの代わりに N/A が表示されます。

全体スコアには成熟度レベルのラベルが付きます。
組織サマリーも、アカウントの平均スコアと最高スコアに、以下のテーブルと同じスコアの区分を適用します。
設問ごとの推奨事項には、その推奨事項を実施すると到達するレベルが示されます（レベル 1 は Reactive、レベル 2 と 3 は Proactive、レベル 4 は Autonomous です）。

| スコア | 成熟度レベル |
| --- | --- |
| 2.0 未満 | Reactive |
| 2.0 以上 3.5 未満 | Proactive |
| 3.5 以上 4.0 以下 | Autonomous |

ルールは `observability_assessment/scoring/` にある決定論的な Python の条件式です。
アセスメントツール自体は成熟度レベルの選択にモデルを使いません。

### 以前のスクリプトからのディスカバリーカタログの変更

チェック 1–50 は ID とカテゴリを維持しています。
チェック 51–52 は CloudWatch Omni のディスカバリーを追加します。
リソースが存在するかどうかではなく、アクティブな設定があるかを結果に反映するため、5 つのチェックで AWS CLI コマンドを変更しました。

| ID | コマンドの変更 |
| --- | --- |
| 12 | `PAUSED`、`DELETED`、`FAILED` のログ異常検出を除外します。 |
| 24 | `--recently-active PT3H` を追加し、過去 3 時間に発行された CloudWatch エージェントのメトリクスだけを対象にします。 |
| 25 | `running` 状態のメトリクスストリームだけを対象にします。 |
| 29 | `aws/spans` ロググループの有無ではなく、`aws xray get-trace-segment-destination`（送信先 `CloudWatchLogs`、ステータス `ACTIVE`）を利用します。 |
| 38 | タグリストが空のリソースを除外します。 |

既存のチェックのうち 13 件の表示名を変更しました。
チェック名をキーにレポートや CSV の行を突き合わせている場合は、可能な範囲で表示名を変更しても変わらないチェック ID を使うか、名前の対応表を更新してください。
`tests/discovery_catalog.json` は、以前のスクリプトの名前ではなく現在のカタログを保持しています。

| ID | 以前の表示名 | 現在の表示名 |
| --- | --- | --- |
| 1 | What percentage of your log groups are categorized by source type (AWS Service Vended Logs, Custom Logs) | What percentage of your log groups are categorized by source type (AWS Service Vended Logs, Custom Logs)? |
| 2 | What percentage of log groups have retention policies configured (example thresholds: …)? | What percentage of the largest log groups have retention policies configured (example thresholds: …)? |
| 3 | Do you have standardized Log Insights queries for common troubleshooting scenarios (errors, latency, security events)? | Do you have standardized Logs Insights queries for common troubleshooting scenarios (errors, latency, security events)? |
| 4 | Do you have a history of Log Insights queries being executed? | Do you have a history of Logs Insights queries being executed? |
| 6 | What percentage of log groups have subscription filters for real-time processing? | What percentage of the largest log groups have subscription filters for real-time processing? |
| 7 | What percentage of EC2 instances have CloudWatch Agent installed with both system metrics AND application logs configured? | What percentage of EC2 instances have the CloudWatch agent installed with both system metrics AND application logs configured? |
| 14 | Have you implemented Cross-Account and Cross-Region Log Centralization? | Have you implemented cross-account and cross-Region log centralization? |
| 19 | What percentage of ECS Clusters have monitoring enabled? | How many ECS clusters are available to monitor? |
| 21 | Do you have EKS clusters with CloudWatch Observability add-on enabled? | Do you have EKS clusters with the CloudWatch Observability add-on enabled? |
| 24 | Are CloudWatch Agents configured to collect system-level metrics? | Is the CloudWatch agent configured to collect system-level metrics? |
| 29 | Do you have transaction search enabled? | Do you have Transaction Search enabled? |
| 44 | Have you configured CloudWatch Investigations action for any alarms? | Have you configured CloudWatch Investigations actions for any alarms? |
| 47 | Do you use AWS Application Signals to monitor application services? | Do you use CloudWatch Application Signals to monitor application services? |

## リージョンの範囲

`--region` で評価の主なリージョンを選択します（デフォルトは `us-west-2`）。
大半のリソース検出は、選択されたリージョンでのみ実行されます。
マルチアカウントの実行では、どの対象アカウントでも同じ選択されたリージョンを評価します。
このアセスメントは全リージョンのインベントリではありません。

現時点の例外には、次のものがあります。

- AWS DevOps Agent のチェックは、`us-east-1` と選択されたリージョンを確認します。
- CloudWatch Omni のチェックは、ドメイン、スペース、インテグレーションの一覧を選択されたリージョンでのみ取得します。
  そのため、ほかのリージョンのスペースは対象にしません。
- CloudWatch Logs の一元化ルールのクエリは、全リージョンのルールの概要を取得します。
- 結果がリージョンに依存しない、グローバルまたはアカウントレベルの API。

アカウントごとのレポートのヘッダーには、アカウント、選択されたリージョン、生成日時が表示されます。
組織サマリーには選択されたリージョンが表示されません。
レポートとあわせて、実行したコマンドやビルドの設定を記録してください。

## 件数を限定したチェックとヒューリスティックなチェック

いくつかのチェックは、アセスメントを現実的な時間で完了させるため、意図して処理の範囲を限定しています。

| チェック対象 | スコープ |
| --- | --- |
| EC2 CloudWatch エージェントのプロセスとログ設定 | SSM で管理されている稼働中インスタンスのうち、API が返した順で最初の 5 件 |
| Lambda JSON ログ設定 | すべての関数 |
| ECS タスクログ | API が返した順で最初の 3 クラスター |
| EKS コントロールプレーンログ | API が返した順で最初の 5 クラスター |
| ログ保持期間 | サイズ降順で 10 件のロググループ |
| ログフィールドインデックス | システム以外のロググループからサイズ降順で 20 件 |
| サブスクリプションフィルター、構造化ログの代替指標（間接的な指標）、古いログの分析 | EC2、ECS、Lambda、EKS のそれぞれについて、特定したロググループからサイズ降順で最大 10 件 |
| アラームアクションのチェック | メトリクスアラームと複合アラームの合計から最初の 50 件 |
| Application Signals のサービス | 直前の 1 時間に観測されたサービス |

これらの結果は、対象の総数が上記の上限を超える場合、網羅的なインベントリではなく目安になります。

一部のチェックはヒューリスティックです。

- アプリケーションの構造化ログの有無は、抽出したロググループに設定されたカスタムフィールドインデックスから推定します。
- Lambda の構造化ログの有無は、ログ形式を指定する一般的な環境変数の値から推定します。
- ECS の構造化ログについては、現時点ではサポートされているタスクのログドライバーをログ設定のエビデンスとし、出力されたイベントは解析しません。
- 使用中のコンピューティングタイプは、一部をロググループの命名パターンから推定します。
- 古いロググループは、コンピューティングのロググループと推定したもののうちサイズの大きいものから選び、最後の取り込みから 90 日を超えたものを古いと判定します。

Q1 では、ディスカバリーチェックが成功し、設定済みリソースを 1 つ以上見つけた場合に限り、そのコンピューティングタイプにログがあるとみなします。
対象のリソースは、CloudWatch エージェントのログを設定した EC2 インスタンス、JSON ログを設定した Lambda 関数、ログを設定した ECS タスク、コントロールプレーンのログタイプを有効にした EKS クラスターです。
チェックが成功しても設定済みリソースが 0 件であれば、カバレッジとして扱いません。
以前のスクリプトは、チェックが成功していればカバレッジが 0% でも加点していたため、以前と比べて Q1 のスコアが下がることがあります。

これらのシグナルをコンプライアンス管理の根拠として利用する前に、ディスカバリーのエビデンスを確認してください。

## ディスカバリーのステータスと空の結果

現時点では、ディスカバリーチェックは、チェックを実行して `None` 以外の値が返ったときに `success` になります。
つまり `success` はチェックから値が返ったことを示し、評価対象の統制が設定されていることを意味しません。

AWS CLI コマンドでのチェックが失敗すると、通常は `None` を返し、エラーとして記録されます。
一方、複数のステップからなるカスタムチェックのいくつかは、例外を捕捉して、空またはゼロ値の結果を返します。
その場合、API の結果を取得できなかった場合でも、リソースが 0 件という評価結果のように見えることがあります。

レポートでは、エビデンスを 1 つも評価できなかった設問を **Not assessed** にします。
一部のエビデンスは得られたものの、ほかのチェックが失敗したか不完全なデータを返した場合、その設問はスコアを保持しますが、**Partial evidence** として示されます。
そのスコアに頼る前に、チェックの詳細を確認してください。

結果が想定と異なる場合は、次の手順で確認します。

1. `--single-check N --debug` で該当のチェックを再実行します。
2. アセスメントのプリンシパルに、ロールテンプレートに記載されたすべてのアクションが付与されていることを確認します。
3. HTML レポートでコマンドとエビデンスを確認します。
4. 権限とサービスの提供状況を確認できるまで、カスタムチェックの空の結果は、結論が出ていないものとして扱います。

CSV には `Status` 列（`Evaluated`、`Partial`、`Unavailable`）が存在します。
チェック 12–50 の大半の行は、リソースの総数ではなく空でない結果が返ったかを示す汎用のバイナリ値を使います。
スプレッドシートの数式として解釈されうるテキストのセルは、先頭にタブを付けて引用符で囲みます。
それらのセルの先頭のタブと改行は、エスケープ表記で書き出されます。
プログラムで CSV を読み込むと、先頭に付けたタブとエスケープ表記はそのまま値として読み込まれます。

## CloudWatch Omni のチェック

チェック 51 と 52 が使うのは、アカウントレベルの CloudWatch Omni のリストオペレーション（`ListSpaces`、`ListDomains`、`ListIntegrations`）だけです。
アセスメントロールには、これらの権限を IAM で付与しています。
Omni はスペース内のリクエストをスペースのアクセスグラント（access grant）でも認可しますが、アセスメントロールにはアクセスグラントを付与していません。
そのため、このツールは Omni のアラート、Omni のダッシュボード、アクセスグラント、クエリしたテレメトリを確認できません。

- アクティブなスペースは、CloudWatch のクロスアカウントオブザーバビリティやログの一元化と同じく、ログ（Q3）とメトリクス（Q7）への統合アクセスのエビデンスとして扱います。
- 組織ドメインに属するスペースは、Q16 のエンタープライズ規模のシグナルとして扱います。
- スペースの一覧を取得できない場合（たとえば権限の不足、古い AWS CLI、選択されたリージョンで Omni が提供されていない場合）、チェック 51 は「Omni なし」ではなくエラーになります。
  インテグレーションの一覧を取得できない場合は、チェック 52 も同様にエラーになります。
- 停止中または移動中のスペースはエビデンスには含まれますが、スコアには影響しません。

## 自動判定で利用されるエビデンスと手動確認が必要な点

大半の成熟度レベルは、AWS 設定のエビデンスから選択されます。
ただし、一部の設問は組織のプラクティスを表しており、サービスの設定だけでは確定できません。

Q16 と Q17 は、設定のエビデンスの組み合わせによって 4 つのレベルのいずれにも判定されます。

- Q16 は、リソースのタグ付け、クロスアカウントオブザーバビリティ（OAM、または組織ドメインのアクティブな CloudWatch Omni スペース）、ダッシュボード、サンプリングした構造化ログのカバレッジ、Application Signals、SLO を利用します。
  アクティブな Omni のインテグレーションは参考情報として報告され、レベルには影響しません。
  レベル 3、レベル 4 と上がるにつれて、標準化とエンタープライズ統合について、より広範なエビデンスが必要になります。
- Q17 は、統合されたダッシュボードとアラームに加えて、サンプリングした保持設定のカバレッジ、アーカイブ、タグ付け、複合アラーム、ログの活用状況、SLO を利用します。
  レベル 4 には、強力なコストガバナンスのエビデンスと、ビジネス目標と協調していることを示す代替指標（正式な SLO）の両方が必要です。

これらは技術的な代替指標です。
チームがトレーニングを受けていること、リーダーシップが継続的改善の文化を推進していること、オブザーバビリティが測定可能な金銭的リターンを生んだことは、AWS の設定からは証明できません。
そのため、レポートの説明では上位のレベルについて手動で確認するための質問を残しています。
このツールでは、手動の回答で結果を上書きできません。

## マルチアカウントの集計

マルチアカウントモードは次のように動作します。

1. 明示的に指定したアカウント ID、または AWS Organizations からアカウントを検出します。
2. 各対象アカウントで `/service-role/ObservabilityAssessmentRole` を引き受けます。
3. `--max-workers`（デフォルトは 5）でアカウントを並行して評価します。
4. アセスメントが成功したアカウントごとに、タイムスタンプ付きのレポートと CSV を 1 つずつ生成します。
5. 評価された設問が 1 つ以上あるアカウントのスコアを平均します。

アセスメント結果を生成する前に失敗したアカウントは別途リスト化され、平均、最小、最大のスコアから除外されます。
成功したアカウントのうち評価された設問がないものは **Not assessed** と表示され、スコアの集計から除外されます。
組織レポートには成功したアカウントの数と、スコアに寄与したアカウントの数の両方が表示されます。
利用できなかったチェックや部分的なエビデンスがあるアカウントにも印が付きます。
現時点のサマリーは成功したアカウントについて、エビデンスの充足度や信頼度のスコアを計算しません。

## クロスアカウントの信頼とパーティションのサポート

テンプレートで作成する対象アカウント用ロールは、設定したアセスメントアカウントの `ObservabilityAssessmentCodeBuildRole` プリンシパルだけを信頼します。
ローカルのプロファイルや名前の異なる自動化ロールにこのロールを引き受けさせる場合は、事前に信頼ポリシーを明示的に変更してください。

マルチアカウントのロール ARN は現時点では商用の `arn:aws` パーティションで組み立てています。
シングルアカウントの CloudFormation リソースは `AWS::Partition` を使いますが、Python のマルチアカウント処理は AWS GovCloud (US) や中国の AWS リージョンに対応していません。

## 再現性

CodeBuild の buildspec は、`AssessmentRepoUrl`（デフォルトは `https://github.com/aws-samples/sample-aws-observability-assessment.git`）で指定したリポジトリを、設定した `AssessmentGitRef`（デフォルトは `main`）でクローンし、クローンしたリポジトリの `requirements.txt` をインストールします。
また、ビルドのたびに AWS CLI を利用可能な最新の v2 リリースに更新します。
オプションの `ExpectedAssessmentCommitSha` パラメータを指定すると、チェックアウトしたコミットが異なる場合にビルドが失敗します。
ソースのコミットを固定しても、実行環境は固定されません。
`requirements.txt` は新しい boto3 のリリースを許容し、CLI の更新はバージョンを指定しないためです。
したがって、同じスタックで 2 回実行しても、ソースのコミットや依存パッケージのバージョンが異なることがあります。

レポートには生成日時が含まれますが、現時点では Git のコミット、アセスメントのスキーマのバージョン、boto3 のバージョン、AWS CLI のバージョンは含まれません。
実際にチェックアウトされた Git のコミットは CodeBuild のログに出力されます。
実行の来歴を正確に残す必要がある場合は、ビルドのログを保存してください。

## 出力と機密データ

アセスメントの出力には、アカウント ID、ARN、リソース名、アカウント名、タグ、設定の詳細が含まれることがあります。
ローカルの出力は `assessment-result/` に書き出され、このディレクトリは gitignore の対象です。
CodeBuild は、HTML、CSV、ZIP アーカイブを、スタック削除後も保持される暗号化されたレポートバケットにアップロードします。

レポートをコミットしたり公開で共有したりする前に、[SCRUBBING.md](SCRUBBING.md) の手順で機密情報を除去し、除去後の出力を手作業で確認してください。

## AI/ML のセキュリティとコンプライアンス

アセスメントツールはオブザーバビリティの成熟度評価の中で次の AWS の AI/ML サービスを取り上げ、その利用を推奨します。

1. **Amazon CloudWatch anomaly detection**（ML ベースのメトリクスの異常検出）
2. **Amazon CloudWatch Investigations**（AI によるインシデント調査の支援）
3. **AWS DevOps Agent**（自然言語による AI を使ったトラブルシューティングの支援）

このツールは AI/ML のモデルをトレーニング、ファインチューニング、デプロイしません。
これらの AWS マネージドサービスが評価対象のアカウントで設定されているかの確認だけを行います。

### アセスメントツールと AI/ML 推論

[評価モデル](#評価モデル)と[自動判定で利用されるエビデンスと手動確認が必要な点](#自動判定で利用されるエビデンスと手動確認が必要な点)で説明したとおり、成熟度のスコアリングのアルゴリズムは決定論的なルールベースです。
このアルゴリズムは `observability_assessment/scoring/` に定義され、評価対象のすべてのアカウントに同じように適用されます。
このツール自体は、推論や予測を行わず、生成 AI も使用しません。
AI/ML に関わる処理は、上記の AI/ML サービスが設定されているかの確認だけに限定されます。

- `cloudwatch:DescribeAnomalyDetectors` を呼び出し、異常検出が設定されているかを確認します。
- AWS DevOps Agent の API を呼び出し、エージェントスペースが存在するかを確認します。
- CloudWatch Investigations のアラームアクションが設定されているかを確認します。

人口統計データや個人データは収集せず、スコアリングにも使いません。
AI/ML サービスの推奨は、サービスが設定されているかだけに基づいており、分析対象のデータの質や性質には基づきません。

### 参照するサービスのセキュリティ統制

参照するサービスには、次の共通の特徴があります。

- お客様のアカウントにすでに存在するオブザーバビリティのデータ（メトリクス、ログ、トレース）を対象に動作します。
- 基盤となるモデルは AWS がフルマネージドで運用し、お客様はアクセスできません。
- お客様のデータがアカウントをまたいで共有されたり、モデルのトレーニングや改善に使われたりすることはありません。
- アクセスは IAM ポリシーで管理されます。
- CloudWatch Investigations と AWS DevOps Agent は、お客様が明示的に有効にしない限り動作しません。

Amazon CloudWatch anomaly detection は、メトリクスのデータが収集された AWS リージョン内でそのデータを扱います。

### コンプライアンスと法務に関する注記

- 参照するすべての AI/ML サービスは AWS マネージドであり、[AWS 責任共有モデル](https://aws.amazon.com/compliance/shared-responsibility-model/)の対象です。
- このツールは AI/ML のモデルをトレーニング、ファインチューニング、デプロイしないため、ツール自体についてデータセットのコンプライアンスレビューは不要です。
- アカウントで AWS の AI/ML サービスを有効にするお客様は、有効にする各サービスについて、該当する [AWS サービス条件](https://aws.amazon.com/service-terms/)と、バイアスと公平性の情報を含む [AWS AI サービスカード](https://aws.amazon.com/machine-learning/responsible-machine-learning/)を確認する責任があります。
- お客様のデータが外部の AI/ML エンドポイントに送信されることはなく、すべての処理はお客様の AWS アカウントとリージョン内で行われます。
  サードパーティの AI/ML サービスやモデルは使用しません。
- AI/ML サービスを有効にするというツールの推奨は情報提供のみを目的としています。
  お客様は本番環境で AI/ML サービスを有効にする前に、社内で必要な承認を得てください。
