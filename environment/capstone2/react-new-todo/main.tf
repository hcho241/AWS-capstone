terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 2.0.0"
    }
  }
  //Terrform State File S3 Bucket
  backend "s3" {
    # Replace this with your bucket name!
   bucket         = "group4-tfstate"
   key            = "state/terraform.tfstate"
   region         = "us-west-2"
  }
}

provider "aws" {
  region  = "us-west-2"
}

resource "aws_codecommit_repository" "imported" {
  repository_name = "Group4Cap2"
  description     = "Group 4 CodeCommit Repository"
}

// S3 bucket
resource "aws_s3_bucket" "group4-cap2-out-bucket" {
  bucket = "group4-cap2-out-bucket"
}


// IAM policy
data "aws_iam_policy_document" "assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["codebuild.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "grp4cap2" {
  name               = "group4-cap2-role"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

data "aws_iam_policy_document" "grp4cap2" {

  statement {
    effect = "Allow"

    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = ["*"]
  }
  
  statement {
    effect = "Allow"

    actions = [
      "ecr:GetAuthorizationToken",
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:GetRepositoryPolicy",
      "ecr:DescribeRepositories",
      "ecr:ListImages",
      "ecr:DescribeImages",
      "ecr:BatchGetImage",
      "ecr:GetLifecyclePolicy",
      "ecr:GetLifecyclePolicyPreview",
      "ecr:ListTagsForResource",
      "ecr:DescribeImageScanFindings",
      "ecr:InitiateLayerUpload",
      "ecr:UploadLayerPart",
      "ecr:CompleteLayerUpload",
      "ecr:PutImage"
    ]

    resources = ["*"]
    
    }
}

resource "aws_iam_role_policy" "grp4cap2" {
  role   = aws_iam_role.grp4cap2.name
  policy = data.aws_iam_policy_document.grp4cap2.json

}

//codebuild

resource "aws_codebuild_project" "group4codebuild" {
  name          = "group4-cap2-project"
  description   = "group4-cap2-project"
  build_timeout = "5"
  service_role  = "arn:aws:iam::962804699607:role/group4-cap2-role"

  artifacts {
    type = "NO_ARTIFACTS"
  }

  cache {
    type     = "S3"
    location = "group4-cap2-out-bucket"
  }

  environment {
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                       = "aws/codebuild/amazonlinux2-x86_64-standard:5.0"
    type                        = "LINUX_CONTAINER"
    image_pull_credentials_type = "CODEBUILD"
    privileged_mode = true

    environment_variable {
      name  = "AWS_ACCESS_KEY_ID"
      value = "AKIA6AK5B2HLQDEQZ7BL"
    }

    environment_variable {
      name  = "AWS_SECRET_ACCESS_KEY"
      value = "5ICvROLOcqXQdWNamdsPGfQLee3EUEAkE8lcS2GT"
    }
  }

  logs_config {
    cloudwatch_logs {
      group_name  = "group4cap2-log-group"
      stream_name = "log-stream"
    }

    s3_logs {
      status   = "ENABLED"
      location = "group4-cap2-out-bucket/build-log"
    }
  }

  source {
    type            = "CODECOMMIT"
    location        = "https://git-codecommit.us-west-2.amazonaws.com/v1/repos/Group4Cap2"
    buildspec       = var.test_buildspec
    git_clone_depth = 1

    git_submodules_config {
      fetch_submodules = true
    }
  }

  tags = {
    Environment = "Group4Cap2"
  }
}

// ECR
resource "aws_ecr_repository" "group4cap2" {
  name = "group4-ecr-repo" 
}

//code pipeline

resource "aws_codepipeline" "group4cap2" {
  name     = "Group4-cap2-pipeline"
  role_arn = "arn:aws:iam::962804699607:role/service-role/AWSCodePipelineGroup4p2"
  
  artifact_store {
    location = "codepipeline-us-west-2-953872164246"
    type     = "S3"
  }
  
  
  stage {
    name = "Source"

    action {
      name             = "Source"
      category         = "Source"
      owner            = "AWS"
      provider         = "CodeCommit"
      version          = "1"
      output_artifacts = ["source_output"]
      
      configuration = {
        RepositoryName  = "Group4Cap2"
        BranchName = "main"
      }

    }
  }

  stage {
    name = "Build"

    action {
      name             = "Build"
      category         = "Build"
      owner            = "AWS"
      provider         = "CodeBuild"
      input_artifacts  = ["source_output"]
      output_artifacts = ["build_output"]
      version          = "1"
     
     configuration = {
        ProjectName  = "group4-cap2-project"
      }
     
    }
  }
  }
  
  //Vpc and subnet
  # Providing a reference to our default VPC
resource "aws_default_vpc" "default_vpc" {
}

# Providing a reference to our default subnets
resource "aws_default_subnet" "default_subnet_a" {
  availability_zone = "us-west-2a"
}

resource "aws_default_subnet" "default_subnet_b" {
  availability_zone = "us-west-2b"
}

resource "aws_default_subnet" "default_subnet_c" {
  availability_zone = "us-west-2c"
}
//ECS Cluster
resource "aws_ecs_cluster" "group4cap2" {
  name = "group4-cap2" # Naming the cluster
}

resource "aws_ecs_task_definition" "group4cap2" {
  family                   = "group4-cap2-task" # Naming our first task
  container_definitions    = <<DEFINITION
  [
    {
      "name": "group4-cap2-task",
      "image": "${aws_ecr_repository.group4cap2.repository_url}",
      "essential": true,
      "portMappings": [
        {
          "containerPort": 3000,
          "hostPort": 3000
        }
      ],
      "memory": 512,
      "cpu": 256
    }
  ]
  DEFINITION
  requires_compatibilities = ["FARGATE"] # Stating that we are using ECS Fargate
  network_mode             = "awsvpc"    # Using awsvpc as our network mode as this is required for Fargate
  memory                   = 512         # Specifying the memory our container requires
  cpu                      = 256         # Specifying the CPU our container requires
  execution_role_arn       = "${aws_iam_role.ecsTaskExecutionRole.arn}"
}

resource "aws_iam_role" "ecsTaskExecutionRole" {
  name               = "group4-cap2-ecsTaskExecutionRole"
  assume_role_policy = "${data.aws_iam_policy_document.assume_role_policy.json}"
}

data "aws_iam_policy_document" "assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy_attachment" "ecsTaskExecutionRole_policy" {
  role       = "${aws_iam_role.ecsTaskExecutionRole.name}"
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_ecs_service" "group4cap2" {
  name            = "group4cap2-service"                             # Naming our first service
  cluster         = "${aws_ecs_cluster.group4cap2.id}"             # Referencing our created Cluster
  task_definition = "${aws_ecs_task_definition.group4cap2.arn}" # Referencing the task our service will spin up
  launch_type     = "FARGATE"
  desired_count   = 3 # Setting the number of containers we want deployed to 3
  
  load_balancer {
    target_group_arn = "${aws_lb_target_group.target_group.arn}" # Referencing our target group
    container_name   = "${aws_ecs_task_definition.group4cap2.family}"
    container_port   = 3000 # Specifying the container port
  }
  
  network_configuration {
    subnets          = ["${aws_default_subnet.default_subnet_a.id}", "${aws_default_subnet.default_subnet_b.id}", "${aws_default_subnet.default_subnet_c.id}"]
    assign_public_ip = true # Providing our containers with public IPs
  }
}

//ALB
resource "aws_alb" "application_load_balancer" {
  name               = "group4cap2-lb-tf" # Naming our load balancer
  load_balancer_type = "application"
  subnets = [ # Referencing the default subnets
    "${aws_default_subnet.default_subnet_a.id}",
    "${aws_default_subnet.default_subnet_b.id}",
    "${aws_default_subnet.default_subnet_c.id}"
  ]
  # Referencing the security group
  security_groups = ["${aws_security_group.load_balancer_security_group.id}"]
}

# Creating a security group for the load balancer:
resource "aws_security_group" "load_balancer_security_group" {
  ingress {
    from_port   = 80 # Allowing traffic in from port 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Allowing traffic in from all sources
  }

  egress {
    from_port   = 0 # Allowing any incoming port
    to_port     = 0 # Allowing any outgoing port
    protocol    = "-1" # Allowing any outgoing protocol 
    cidr_blocks = ["0.0.0.0/0"] # Allowing traffic out to all IP addresses
  }
}

resource "aws_lb_target_group" "target_group" {
  name        = "target-group"
  port        = 80
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = "${aws_default_vpc.default_vpc.id}" # Referencing the default VPC
  health_check {
    matcher = "200,301,302"
    path = "/"
  }
}

resource "aws_lb_listener" "listener" {
  load_balancer_arn = "${aws_alb.application_load_balancer.arn}" # Referencing our load balancer
  port              = "80"
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = "${aws_lb_target_group.target_group.arn}" # Referencing our tagrte group
  }
}

//S3 bucket where the todo lists are stored
resource "aws_s3_bucket" "group4-capstone2-bucket" {
  bucket = "group4-capstone2-bucket"
}

//Lambda Function
data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "iam_for_lambda" {
  name               = "group4_GetTodos_lambda_role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}


resource "aws_lambda_function" "group4cap2" {
  # If the file is not in the current working directory you will need to include a
  # path.module in the filename.
  filename      = "lambda_function_payload.zip"
  function_name = "group4-cap2-GetTodos"
  role          = aws_iam_role.iam_for_lambda.arn
  handler       = "lambda.lambda_handler"

 runtime = "python3.9"
  
}

//API Gateway

resource "aws_lambda_permission" "apigw-post" {
  //statement_id  = "Group4-GetTodo-AllowAPIGatewayInvokePOST"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.group4cap2.function_name
  principal     = "apigateway.amazonaws.com"

  source_arn = "${aws_api_gateway_rest_api.rest_api.execution_arn}/*"
}

resource "aws_api_gateway_rest_api" "rest_api" {
  name = "Group4-GetTodo"

  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

//api resource
resource "aws_api_gateway_resource" "api_gw_todo_resource" {
  parent_id   = aws_api_gateway_rest_api.rest_api.root_resource_id
  path_part   = "get-todo"
  rest_api_id = aws_api_gateway_rest_api.rest_api.id
}

//api method

resource "aws_api_gateway_method" "api_gw_todo_method" {
  authorization = "NONE"
  http_method   = "GET"
  resource_id   = aws_api_gateway_resource.api_gw_todo_resource.id
  rest_api_id   = aws_api_gateway_rest_api.rest_api.id
}

resource "aws_api_gateway_integration" "api_gw_todo_intg" {
  http_method             = aws_api_gateway_method.api_gw_todo_method.http_method
  resource_id             = aws_api_gateway_resource.api_gw_todo_resource.id
  rest_api_id             = aws_api_gateway_rest_api.rest_api.id
  type                    = "AWS"
  integration_http_method = "POST"
  uri                     = aws_lambda_function.group4cap2.invoke_arn
}

resource "aws_api_gateway_method_response" "response_200" {
  rest_api_id = aws_api_gateway_rest_api.rest_api.id
  resource_id = aws_api_gateway_resource.api_gw_todo_resource.id
  http_method = aws_api_gateway_method.api_gw_todo_method.http_method
  status_code = "200"
  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = true,
    "method.response.header.Access-Control-Allow-Methods" = true,
    "method.response.header.Access-Control-Allow-Origin"  = true
  }
}

resource "aws_api_gateway_integration_response" "api_gw_intg_resp" {
  rest_api_id      = aws_api_gateway_rest_api.rest_api.id
  resource_id      = aws_api_gateway_resource.api_gw_todo_resource.id
  http_method      = aws_api_gateway_method.api_gw_todo_method.http_method
  status_code      = aws_api_gateway_method_response.response_200.status_code
  content_handling = "CONVERT_TO_TEXT"
  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = "'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token'",
    "method.response.header.Access-Control-Allow-Methods" = "'GET,OPTIONS'",
    "method.response.header.Access-Control-Allow-Origin"  = "'*'"
  }
}

resource "aws_api_gateway_deployment" "api_gw_deployment" {
  rest_api_id = aws_api_gateway_rest_api.rest_api.id

  triggers = {
      redeployment = sha1(jsonencode([
      aws_api_gateway_resource.api_gw_todo_resource.id,
      aws_api_gateway_method.api_gw_todo_method.id,
      aws_api_gateway_integration.api_gw_todo_intg.id,
      aws_api_gateway_integration_response.api_gw_intg_resp.id,
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_api_gateway_stage" "api_gw_stage_prod" {
  deployment_id = aws_api_gateway_deployment.api_gw_deployment.id
  rest_api_id   = aws_api_gateway_rest_api.rest_api.id
  stage_name    = "Prod"
}


