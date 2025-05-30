CREATE TABLE [PS_GameLog].[dbo].[IPBlocked] (
    [Id] INT IDENTITY(1,1) PRIMARY KEY,
    [LogTime] DATETIME NOT NULL,
    [Hostname] NVARCHAR(255) NULL,
    [GameCode] NVARCHAR(255) NULL,
    [ClientId] INT NULL,
    [IP] NVARCHAR(50) NULL,
    [MAC] NVARCHAR(50) NULL,
    [HardwareId] NVARCHAR(255) NULL,
    [Message] NVARCHAR(MAX) NULL
)
