USE [PS_GameLog];
GO

-- Tabella principale per log generici e detection
CREATE TABLE [dbo].[gameLog] (
    [Id] INT IDENTITY(1,1) PRIMARY KEY,
    [LogTime] DATETIME NOT NULL DEFAULT GETDATE(),
    [Hostname] NVARCHAR(255) NULL,
    [GameCode] NVARCHAR(64) NULL,
    [ClientId] INT NULL,
    [IP] NVARCHAR(64) NULL,
    [MAC] NVARCHAR(32) NULL,
    [HardwareId] NVARCHAR(255) NULL,
    [Message] NVARCHAR(4000) NULL
);
GO

-- Tabella per eventi di login
CREATE TABLE [dbo].[LoginEvents] (
    [Id] INT IDENTITY(1,1) PRIMARY KEY,
    [ClientId] INT NOT NULL,
    [Username] NVARCHAR(100) NULL,
    [LoginTime] DATETIME NOT NULL,
    [IP] NVARCHAR(64) NULL
);
GO

-- Tabella per eventi di logout
CREATE TABLE [dbo].[LogoutEvents] (
    [Id] INT IDENTITY(1,1) PRIMARY KEY,
    [ClientId] INT NOT NULL,
    [LogoutTime] DATETIME NOT NULL
);
GO

-- Tabella per eventi generici (custom)
CREATE TABLE [dbo].[EventLog] (
    [Id] INT IDENTITY(1,1) PRIMARY KEY,
    [EventTime] DATETIME NOT NULL DEFAULT GETDATE(),
    [ClientId] INT NULL,
    [EventType] NVARCHAR(100) NULL,
    [EventData] NVARCHAR(2000) NULL
);
GO
