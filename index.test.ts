import { validateIMRolePolicy } from './index';

describe('', () => {
    it('Resource with asterisk', () => {
        const validPolicy = JSON.stringify(
            {
                "PolicyName": "root",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "IamListAccess",
                            "Effect": "Allow",
                            "Action": [
                                "iam:ListRoles",
                                "iam:ListUsers"
                            ],
                            "Resource": "*"
                        }
                    ]
                }
            });
        expect(validateIMRolePolicy(validPolicy)).toBe(false);
    });
});

describe('', () => {
    it('PolicyName with 1 char', () => {
        const validPolicy = JSON.stringify(
            {
                "PolicyName": "T",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "IamListAccess",
                            "Effect": "Allow",
                            "Action": [
                                "iam:ListRoles",
                                "iam:ListUsers"
                            ],
                            "Resource": ""
                        }
                    ]
                }
            });
        expect(validateIMRolePolicy(validPolicy)).toBe(true);
    });

    it('PolicyName with 128 chars', () => {
        const validPolicy = JSON.stringify(
            {
                "PolicyName": "TESTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "IamListAccess",
                            "Effect": "Allow",
                            "Action": [
                                "iam:ListRoles",
                                "iam:ListUsers"
                            ],
                            "Resource": ""
                        }
                    ]
                }
            });
        expect(validateIMRolePolicy(validPolicy)).toBe(true);
    });

    it('PolicyName with 0 chars', () => {
        const validPolicy = JSON.stringify(
            {
                "PolicyName": "",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "IamListAccess",
                            "Effect": "Allow",
                            "Action": [
                                "iam:ListRoles",
                                "iam:ListUsers"
                            ],
                            "Resource": ""
                        }
                    ]
                }
            });
        expect(validateIMRolePolicy(validPolicy)).toBe(false);
    });  

    it('PolicyName with 129 chars', () => {
        const validPolicy = JSON.stringify(
            {
                "PolicyName": "TESTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "IamListAccess",
                            "Effect": "Allow",
                            "Action": [
                                "iam:ListRoles",
                                "iam:ListUsers"
                            ],
                            "Resource": ""
                        }
                    ]
                }
            });
        expect(validateIMRolePolicy(validPolicy)).toBe(false);
    });

    it('PolicyName with 10 chars', () => {
        const validPolicy = JSON.stringify(
            {
                "PolicyName": "TESTTTTTTT",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "IamListAccess",
                            "Effect": "Allow",
                            "Action": [
                                "iam:ListRoles",
                                "iam:ListUsers"
                            ],
                            "Resource": ""
                        }
                    ]
                }
            });
        expect(validateIMRolePolicy(validPolicy)).toBe(true);
    });

    it('PolicyName with number', () => {
        const validPolicy = JSON.stringify(
            {
                "PolicyName": 777,
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "IamListAccess",
                            "Effect": "Allow",
                            "Action": [
                                "iam:ListRoles",
                                "iam:ListUsers"
                            ],
                            "Resource": ""
                        }
                    ]
                }
            });
        expect(validateIMRolePolicy(validPolicy)).toBe(false);
    });

    it('PolicyName non-matching regex function', () => {
        const validPolicy = JSON.stringify(
            {
                "PolicyName": "jestem przebrzydlym hasztagiem #",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "IamListAccess",
                            "Effect": "Allow",
                            "Action": [
                                "iam:ListRoles",
                                "iam:ListUsers"
                            ],
                            "Resource": ""
                        }
                    ]
                }
            });
        expect(validateIMRolePolicy(validPolicy)).toBe(false);
    });
});