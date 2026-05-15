import json
import boto3
import time

ssm = boto3.client("ssm", region_name="ap-northeast-2")
INSTANCE_ID = "i-099aaa2aac41dc6a1"

def lambda_handler(event, context):
    # SSM으로 EC2에서 scanner.py 실행 (스캔 + AI분석 + S3 업로드)
    response = ssm.send_command(
        InstanceIds=[INSTANCE_ID],
        DocumentName="AWS-RunShellScript",
        Parameters={
            "commands": [
                "cd /home/ubuntu/awvs-scripts && sudo python3 scanner.py 2>&1"
            ],
            "executionTimeout": ["240"]
        },
        TimeoutSeconds=240
    )

    command_id = response["Command"]["CommandId"]

    # 결과 대기 (최대 200초 - AI분석 시간 고려)
    for _ in range(40):
        time.sleep(5)
        try:
            result = ssm.get_command_invocation(
                CommandId=command_id,
                InstanceId=INSTANCE_ID
            )
            if result["Status"] in ["Success", "Failed", "TimedOut"]:
                return {
                    "statusCode": 200,
                    "body": json.dumps({
                        "status": result["Status"],
                        "output": result["StandardOutputContent"][:3000],
                        "error": result["StandardErrorContent"][:1000]
                    }, ensure_ascii=False)
                }
        except ssm.exceptions.InvocationDoesNotExist:
            continue

    return {
        "statusCode": 202,
        "body": json.dumps({
            "status": "running",
            "command_id": command_id,
            "message": "스캔 진행 중. command_id로 결과 조회 가능"
        })
    }
