import fs from 'fs';

type Statement = {
    Effect: "Allow" | "Deny";
    Action: string | string[];
    Resource: string;

    Sid?: string;
    Principal?: Record<string, string[]>;
    NotPrincipal?: Record<string, string[]>;
    NoAction?: string;
    NoResource?: string[];
    Condition?: unknown;
}

type PolicyDocument = {
    Version: "2008-10-17" | "2012-10-17";
    Statement: Statement | Statement[];
}

export type IMRolePolicy = {
    PolicyName: string;
    PolicyDocument: PolicyDocument;
}

const pattern = /^[\w+=,.@-]+$/;

const filePath = './files/IMRolePolicy.json';

const loadFile = (): string | undefined => {
    try {
        return fs.readFileSync(filePath, 'utf8');
    } catch (e) {
        console.error("Error while loading file:", e);
        return undefined;
    }
}

const json = loadFile();

export const validateIMRolePolicy = (json: string | undefined): boolean => {
    if (typeof json !== 'string') {
        return false;
    }
    try {
        const policy = JSON.parse(json) as IMRolePolicy;
        if (typeof policy.PolicyName !== 'string' ||
            !(policy.PolicyName.length >= 1 && policy.PolicyName.length <= 128) ||
            !pattern.test(policy.PolicyName)) {
            return false;
        }

        if (typeof policy.PolicyDocument !== 'object' ||
            !['2008-10-17', '2012-10-17'].includes(policy.PolicyDocument.Version) ||
            !(Array.isArray(policy.PolicyDocument.Statement) || typeof policy.PolicyDocument.Statement === 'object')) {
            return false;
        }

        const statements = Array.isArray(policy.PolicyDocument.Statement) ? policy.PolicyDocument.Statement : [policy.PolicyDocument.Statement];
        for (const statement of statements) {
            if (!['Allow', 'Deny'].includes(statement.Effect) ||
                !(typeof statement.Action === 'string' || Array.isArray(statement.Action))) {
                return false;
            }
            // check for single asterisk
            if (typeof statement.Resource !== 'string') {
                return false;
            } else {
                if (statement.Resource === '*') return false
            }

            if (statement.Sid && typeof statement.Sid !== 'string') {
                return false;
            }
            if (statement.Principal && typeof statement.Principal !== 'object') {
                return false;
            }
            if (statement.NotPrincipal && typeof statement.NotPrincipal !== 'object') {
                return false;
            }
            if (statement.NoAction && typeof statement.NoAction !== 'string') {
                return false;
            }
            if (statement.NoResource && !Array.isArray(statement.NoResource)) {
                return false;
            }

        }
    } catch (e) {
        console.log(e);
        return false;
    }

    return true;
}

console.log(validateIMRolePolicy(json));