import fs from 'fs';

type IMRolePolicy = {
    PolicyName: string;
    PolicyDocument: object;
}

const pattern = new RegExp("[\\w+=,.@-]+");

const loadFile = (): string | undefined => {
    try {
        return fs.readFileSync('./files/IMRolePolicy.json', 'utf8');
    } catch (e) {
        console.error("Error while loading file:", e);
        return undefined;
    }
}

const json = loadFile();

// https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-role-policy.html
const validateIMRolePolicy = (json: string | undefined): boolean => {
    if (typeof json !== 'string') {
        return false;
    }
    try {
        const policy = JSON.parse(json) as IMRolePolicy;
        if (typeof policy.PolicyName !== 'string' &&
            ((policy.PolicyName >= 1 && policy.PolicyName <= 128) ||
                pattern.test(policy.PolicyName))
        ) {
            return false;
        }
        // https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html
        // todo
        if (typeof policy.PolicyDocument !== 'object') {
            return false;
        }
    } catch (e) {
        console.log(e);
        return false;
    }

    return true;
}

console.log(validateIMRolePolicy(json));