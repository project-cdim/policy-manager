CREATE TABLE IF NOT EXISTS  policies(
policyID varchar(10) PRIMARY KEY,
category text Not NULL,
title text Not NULL,
policy jsonb Not NULL,
enabled bool Not NULL,
createdAt timestamp Not NULL,
updatedAt timestamp Not NULL);

INSERT into policies (policyID, category,title, policy,enabled,createdAt,updatedAt)
VALUES 
('123456789a','nodeConfigurationPolicy','test','{"hardwareConnectionsLimit": {"gpu": {"maxNum": 5, "minNum": 1}}}',False,'2023/09/21' ,'2023/09/21'),
('123456789c','nodeConfigurationPolicy','test','{"hardwareConnectionsLimit": {"dsp": {"maxNum": 5, "minNum": 1}}}',True,'2023/09/21' ,'2023/09/21'),
('123456789b','systemOperationPolicy','test','{"useThreshold": {"gpu": {"value": 80, "unit": "percent", "comparision": "gt"}}}',False,'2023/09/28' ,'2023/09/28'),
('123456789d','systemOperationPolicy','test','{"useThreshold": {"dsp": {"value": 80, "unit": "percent", "comparision": "lt"}}}',True,'2023/09/28' ,'2023/09/28');

