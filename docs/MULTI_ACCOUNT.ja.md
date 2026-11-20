# マルチアカウントアセスメント

[English](MULTI_ACCOUNT.md) | 日本語

このガイドでは、複数の AWS アカウントを対象にアセスメントをデプロイします。
シングルアカウントのアセスメントについては[クイックスタート](../README.ja.md#クイックスタート)を参照してください。
アセスメント後にリソースを削除する手順は[クリーンアップ](CLEANUP.ja.md)を参照してください。

## 目次

- [推奨する中央アカウント](#推奨する中央アカウント)
- [1. 対象アカウントにアセスメントロールをデプロイする](#1-対象アカウントにアセスメントロールをデプロイする)
- [2. アカウントの検出方法を選ぶ](#2-アカウントの検出方法を選ぶ)
- [3. 中央アカウントに CodeBuild をデプロイする](#3-中央アカウントに-codebuild-をデプロイする)
- [オプション: マルチアカウントモードをローカルで実行する](#オプション-マルチアカウントモードをローカルで実行する)

マルチアカウントモードでは、中央のアセスメントアカウントで CodeBuild を実行し、各対象アカウントの `ObservabilityAssessmentRole` を引き受けて、組織サマリーと、正常に完了したアカウントのレポートを生成します。
サマリーで成功したアカウント数と失敗したアカウント数を確認し、想定どおりのアカウントごとのファイルがあることを確かめてください。
すべての対象アカウントでアセスメントが失敗しても、サマリーレポートは生成されるため、ビルドは成功と扱われます。

## 推奨する中央アカウント

組織全体をスキャンする場合は、Organizations の管理アカウントではなくセキュリティ、ツール、オブザーバビリティ専用のアカウントのような、委任管理者として登録したメンバーアカウントから CodeBuild を実行してください。
これは AWS の[管理アカウントのベストプラクティス][orgs-mgmt-best-practices]に沿った構成です。
このベストプラクティスでは、ワークロードや日常的に使うツールを管理アカウントに置かず、管理アカウントへのアクセスを制限することを推奨しています。

委任管理者のアカウントを中央アカウントにする場合は、次のように構成します。

- [アカウントを StackSets の委任管理者として登録][stacksets-delegated-admin]した後、`--call-as DELEGATED_ADMIN` を指定して対象ロールの StackSet をデプロイします。
- OU からのアカウント検出は管理アカウントから一度だけ適用する [Organizations のリソースポリシー](#委任ツールアカウント向けの-organizations-リソースポリシー)で許可します。
  ほかのサービスの委任管理者として登録しても、これらのオペレーションは許可されません。
- 管理アカウントも評価する必要がある場合に限り、テンプレート 1 を管理アカウントに個別のスタックとしてデプロイします。

## 1. 対象アカウントにアセスメントロールをデプロイする

### 対象アカウントへの個別デプロイ

対象アカウントが少ない場合は、`1-observability-assessment-role.yaml` を各対象アカウントに個別にデプロイします。

各対象アカウントの認証情報で、以下のコマンドを実行してください。

```bash
CENTRAL_ID=123456789012

aws cloudformation create-stack \
  --stack-name ObservabilityAssessmentRole \
  --template-body file://1-observability-assessment-role.yaml \
  --parameters ParameterKey=AssessmentAccountID,ParameterValue="$CENTRAL_ID" \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-west-2
```

### 組織規模の StackSet デプロイ

組織規模でデプロイする場合は、サービスマネージド型の CloudFormation StackSet を使います。
StackSets の委任管理者として登録したアカウントから実行する場合は `DELEGATED_ADMIN`（推奨）を、Organizations の管理アカウントで実行する場合は `SELF` を使います。
StackSets の 2 つのコマンドには、同じ `--call-as` の値を指定してください。

```bash
CENTRAL_ID=123456789012
STACKSET_CALL_AS=DELEGATED_ADMIN

aws cloudformation create-stack-set \
  --stack-set-name ObservabilityAssessmentRole \
  --template-body file://1-observability-assessment-role.yaml \
  --parameters ParameterKey=AssessmentAccountID,ParameterValue="$CENTRAL_ID" \
  --capabilities CAPABILITY_NAMED_IAM \
  --permission-model SERVICE_MANAGED \
  --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
  --call-as "$STACKSET_CALL_AS" \
  --region us-west-2

OPERATION_ID=$(aws cloudformation create-stack-instances \
  --stack-set-name ObservabilityAssessmentRole \
  --deployment-targets OrganizationalUnitIds=ou-xxxx-xxxxxxxx \
  --regions us-west-2 \
  --operation-preferences FailureToleranceCount=5,MaxConcurrentCount=6 \
  --call-as "$STACKSET_CALL_AS" --region us-west-2 \
  --query OperationId --output text)

aws cloudformation describe-stack-set-operation \
  --stack-set-name ObservabilityAssessmentRole \
  --operation-id "$OPERATION_ID" --call-as "$STACKSET_CALL_AS" \
  --query 'StackSetOperation.[Status,StatusReason]' --output table \
  --region us-west-2
aws cloudformation list-stack-instances \
  --stack-set-name ObservabilityAssessmentRole \
  --call-as "$STACKSET_CALL_AS" --region us-west-2 --output table
```

中央の CodeBuild プロジェクトをデプロイする前に、オペレーションの完了を待ち、すべての対象スタックインスタンスを確認してください。
`FailureToleranceCount=5` では、一部のインスタンスが失敗してもオペレーションが成功になることがあるため、評価するすべてのアカウントに対象ロールが存在することを確かめてください。
個別のスタックでロールをデプロイした場合は、各アカウントでスタックの作成完了を待ちます。
これらのコマンドは [StackSets の信頼されたアクセス][stacksets-trusted-access]を有効にした後に実行してください。

IAM ロールはグローバルなリソースのため、この StackSet は 1 つのリージョンにだけデプロイします。
StackSets は管理アカウントにスタックインスタンスをデプロイしないため、管理アカウントも評価する必要がある場合は、テンプレート 1 を管理アカウントに個別のスタックとしてデプロイします。

付属の信頼ポリシーは `CENTRAL_ASSESSMENT_ACCOUNT_ID` にある指定の CodeBuild ロールにだけ、対象ロールを引き受けることを許可します。
別の自動化ロールやローカルのプリンシパルが対象ロールを引き受ける必要がある場合は、信頼ポリシーを意図して拡張してください。

## 2. アカウントの検出方法を選ぶ

次のどちらかを使います。

- `AssessmentAccounts`：アカウント ID をカンマ区切りで明示的に列挙します。
  Organizations の検出権限は不要です。
- `AssessmentOUs`：カンマ区切りで指定した 1 つ以上のルートまたは OU の配下にあるアカウントを検出します。
  中央アカウントには、このツールが使う Organizations の読み取りオペレーションの権限が必要です。

### 委任ツールアカウント向けの Organizations リソースポリシー

委任ツールアカウントで CodeBuild を実行する場合は、管理アカウントから Organizations のリソースポリシーを設定し、検出オペレーションを許可できます。

```bash
aws organizations put-resource-policy --content \
  '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "AllowObservabilityAssessmentAccountDiscovery",
        "Effect": "Allow",
        "Principal": {
          "AWS": "arn:aws:iam::CENTRAL_ASSESSMENT_ACCOUNT_ID:root"
        },
        "Action": [
          "organizations:ListAccounts",
          "organizations:ListAccountsForParent",
          "organizations:ListOrganizationalUnitsForParent",
          "organizations:DescribeAccount",
          "organizations:DescribeOrganization"
        ],
        "Resource": "*"
      }
    ]
  }'
```

ほかの AWS サービスの委任管理者として登録しても、このツールが使う Organizations API のオペレーションは許可されません。

## 3. 中央アカウントに CodeBuild をデプロイする

ロールは対象アカウントに別途デプロイ済みのため、`CreateAssessmentRole=no` を設定します。
以下の例は明示的に列挙したアカウントを評価します。

```bash
TARGET_ID=111111111111

aws cloudformation create-stack \
  --stack-name ObservabilityAssessmentCodeBuild \
  --template-body file://2-observability-assessment-codebuild.yaml \
  --parameters ParameterKey=AssessmentRegion,ParameterValue=us-west-2 \
               ParameterKey=CreateAssessmentRole,ParameterValue=no \
               ParameterKey=AssessmentAccounts,ParameterValue="$TARGET_ID" \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-west-2
```

組織の範囲からアカウントを検出するには、`AssessmentAccounts` を `AssessmentOUs` パラメータに置き換えます。

```text
ParameterKey=AssessmentOUs,ParameterValue=ou-xxxx-aaaaaaaa
```

## オプション: マルチアカウントモードをローカルで実行する

以下のコマンドは、対象ロールの信頼ポリシーがローカルのプリンシパルによる `/service-role/ObservabilityAssessmentRole` の引き受けを許可している場合に限り動作します。

```bash
# Explicit accounts
python3 observability_assessment_comprehensive.py \
  --profile YOUR_PROFILE \
  --region us-west-2 \
  --accounts 111111111111,222222222222

# Root or OU scope
python3 observability_assessment_comprehensive.py \
  --profile YOUR_PROFILE \
  --region us-west-2 \
  --ou ou-xxxx-aaaaaaaa,ou-xxxx-bbbbbbbb
```

[stacksets-trusted-access]: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-orgs-enable-trusted-access.html
[orgs-mgmt-best-practices]: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_best-practices_mgmt-acct.html
[stacksets-delegated-admin]: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-orgs-delegated-admin.html
