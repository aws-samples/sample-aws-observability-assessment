# クリーンアップ

[English](CLEANUP.md) | 日本語

リソースは作成したときと逆の順序で削除します。
CloudFormation は、スタックが所有しない依存リソースが残っている場合、そのスタックを削除できません。
そのため、スタックや StackSet を削除する前に、保持された S3 バケットを空にし、StackSet のインスタンスを削除してください。
リージョンと識別子は、デプロイしたときの値に置き換えてください。

## 1. レポートバケットを空にして削除する

レポートバケットとそのアクセスログ用バケットは `DeletionPolicy: Retain` で宣言され、バージョニングが有効になっています。
そのため、CodeBuild スタックを削除しても、両方のバケットとその内容は残ります。
バージョニングが有効なため、`aws s3 rm --recursive` は削除マーカーを追加するだけで、すべてのオブジェクトバージョンと削除マーカーを削除するまで `delete-bucket` は `BucketNotEmpty` で失敗します。
以下のコマンドは、それらを 1 回に最大 1,000 件ずつ削除します。
実行には `jq` が必要です。
S3 コンソールの **Empty** でも、すべてのバージョンを削除できます。
この操作は元に戻せないため、必要なレポートの履歴はバケットを空にする前に保存してください。

```bash
REPORT_BUCKET=$(aws cloudformation describe-stacks \
  --stack-name ObservabilityAssessmentCodeBuild \
  --query "Stacks[0].Outputs[?OutputKey=='ReportBucketName'].OutputValue" \
  --output text --region us-west-2)

# Delete every object version and delete marker, up to 1,000 per request.
empty_bucket() {
  while true; do
    OBJS=$(aws s3api list-object-versions --bucket "$1" \
      --max-keys 1000 --no-paginate --output json --region us-west-2 \
      --query '{Objects: [Versions[].{Key:Key,VersionId:VersionId}, DeleteMarkers[].{Key:Key,VersionId:VersionId}][], Quiet: `true`}')
    [ "$(echo "$OBJS" | jq '.Objects | length')" -eq 0 ] && break
    aws s3api delete-objects --bucket "$1" --delete "$OBJS" --region us-west-2
  done
}

empty_bucket "$REPORT_BUCKET"
aws s3api delete-bucket --bucket "$REPORT_BUCKET" --region us-west-2
```

アクセスログ用バケットは、レポートバケットの後に削除します。
サーバーアクセスログはベストエフォートで配信され、上記の削除リクエストの記録を含め、数時間後に届くことがあるため、時間を置いてから空にしてください。
それでも `delete-bucket` が `BucketNotEmpty` を返す場合は、もう一度 `empty_bucket` を実行します。

```bash
LOG_BUCKET=$(aws cloudformation describe-stack-resource \
  --stack-name ObservabilityAssessmentCodeBuild \
  --logical-resource-id ReportBucketAccessLogs \
  --query StackResourceDetail.PhysicalResourceId \
  --output text --region us-west-2)

empty_bucket "$LOG_BUCKET"
aws s3api delete-bucket --bucket "$LOG_BUCKET" --region us-west-2
```

## 2. CodeBuild スタックを削除する

バケットを空にしたら、CodeBuild プロジェクト、その IAM ロール、Lambda トリガー、バケットのリソースを作成したスタックを削除します。
シングルアカウントモード（`CreateAssessmentRole=yes`）では、このスタックがアセスメントロールも作成しているため、ここでアセスメントロールも削除されます。

```bash
aws cloudformation delete-stack \
  --stack-name ObservabilityAssessmentCodeBuild --region us-west-2
aws cloudformation wait stack-delete-complete \
  --stack-name ObservabilityAssessmentCodeBuild --region us-west-2
```

## 3. 対象アカウントからアセスメントロールを削除する

シングルアカウントモードでは、ロールはステップ 2 で CodeBuild スタックとともに削除されているため、このステップは不要です。
マルチアカウント構成では、`1-observability-assessment-role.yaml` でデプロイしたロールを削除します。

アカウントごとに個別のスタックをデプロイした場合は、各対象アカウントの認証情報でスタックを削除します。

```bash
aws cloudformation delete-stack \
  --stack-name ObservabilityAssessmentRole --region us-west-2
aws cloudformation wait stack-delete-complete \
  --stack-name ObservabilityAssessmentRole --region us-west-2
```

サービスマネージド型の StackSet の場合は、先にスタックインスタンスを削除し、その後で StackSet 自体を削除します。
`--call-as` には、デプロイしたときと同じ値を指定してください。
委任管理者として登録したアカウントからは `DELEGATED_ADMIN`、Organizations の管理アカウントからは `SELF` で実行してください。

```bash
STACKSET_CALL_AS=DELEGATED_ADMIN

OPERATION_ID=$(aws cloudformation delete-stack-instances \
  --stack-set-name ObservabilityAssessmentRole \
  --deployment-targets OrganizationalUnitIds=ou-xxxx-xxxxxxxx \
  --regions us-west-2 --no-retain-stacks \
  --call-as "$STACKSET_CALL_AS" --region us-west-2 \
  --query OperationId --output text)

aws cloudformation describe-stack-set-operation \
  --stack-set-name ObservabilityAssessmentRole \
  --operation-id "$OPERATION_ID" --call-as "$STACKSET_CALL_AS" \
  --query 'StackSetOperation.[Status,StatusReason]' --output table \
  --region us-west-2

# After the instance-deletion operation reports SUCCEEDED:
aws cloudformation delete-stack-set \
  --stack-set-name ObservabilityAssessmentRole \
  --call-as "$STACKSET_CALL_AS" --region us-west-2
```

管理アカウントも評価するために、Organizations の管理アカウントにテンプレート 1 の個別のスタックをデプロイした場合は、上記の手順でそのスタックも別途削除してください。

## 4. Organizations リソースポリシーを削除する

[Organizations のリソースポリシー](MULTI_ACCOUNT.ja.md#委任ツールアカウント向けの-organizations-リソースポリシー)を追加して委任ツールアカウントの OU 検出を許可している場合は、そのステートメントを必要とするアカウントがなくなった時点で、追加したステートメントを削除します。
それがポリシー内で唯一のものであれば、管理アカウントからリソースポリシーを削除します。

```bash
aws organizations delete-resource-policy
```

ポリシーにほかに必要なステートメントがある場合は、ポリシー全体を削除せず、`aws organizations put-resource-policy` でポリシーを編集して `AllowObservabilityAssessmentAccountDiscovery` ステートメントだけを削除してください。

## 5. ローカル出力を削除する

ローカルでの実行はレポートを `assessment-result/` に書き出し、このディレクトリは gitignore の対象です。
ローカルのレポートを消去するには、このディレクトリを削除します。
